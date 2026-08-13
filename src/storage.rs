use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("head changed concurrently (expected {expected:?}, actual {actual:?})")]
pub struct CasConflict {
    pub expected: Option<String>,
    pub actual: Option<String>,
}

pub trait Storage {
    fn put_object_if_absent(&self, kind: ObjectKind, id: &str, data: &[u8]) -> Result<()>;
    fn get_object(&self, kind: ObjectKind, id: &str) -> Result<Vec<u8>>;
    fn read_head(&self) -> Result<Option<String>>;
    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()>;
}

#[derive(Clone, Copy)]
pub enum ObjectKind {
    Pack,
    Manifest,
    Policy,
}

impl ObjectKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Pack => "objects",
            Self::Manifest => "manifests",
            Self::Policy => "policies",
        }
    }
}

#[derive(Clone)]
pub struct FilesystemStorage {
    root: PathBuf,
}

impl FilesystemStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn initialize(&self) -> Result<()> {
        fs::create_dir_all(self.root.join("objects"))?;
        fs::create_dir_all(self.root.join("manifests"))?;
        fs::create_dir_all(self.root.join("policies"))?;
        Ok(())
    }

    fn object_path(&self, kind: ObjectKind, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        Ok(self.root.join(kind.directory()).join(&id[..2]).join(id))
    }

    fn lock_file(&self) -> Result<File> {
        self.initialize()?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("HEAD.lock"))
            .context("open HEAD lock")
    }

    fn sync_directory(path: &Path) -> Result<()> {
        File::open(path)?.sync_all()?;
        Ok(())
    }
}

impl Storage for FilesystemStorage {
    fn put_object_if_absent(&self, kind: ObjectKind, id: &str, data: &[u8]) -> Result<()> {
        self.initialize()?;
        let target = self.object_path(kind, id)?;
        let parent = target.parent().expect("object path has parent");
        fs::create_dir_all(parent)?;
        if target.exists() {
            let existing = fs::read(&target)?;
            if existing != data {
                bail!("object id collision for {id}")
            }
            return Ok(());
        }

        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let temporary = parent.join(format!(".tmp-{}", hex::encode(random)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;

        match fs::hard_link(&temporary, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read(&target)? != data {
                    let _ = fs::remove_file(&temporary);
                    bail!("object id collision for {id}")
                }
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        fs::remove_file(&temporary)?;
        Self::sync_directory(parent)?;
        Ok(())
    }

    fn get_object(&self, kind: ObjectKind, id: &str) -> Result<Vec<u8>> {
        let path = self.object_path(kind, id)?;
        fs::read(&path).with_context(|| format!("read {}", path.display()))
    }

    fn read_head(&self) -> Result<Option<String>> {
        let path = self.root.join("HEAD");
        match fs::read_to_string(path) {
            Ok(value) => {
                let value = value.trim().to_owned();
                validate_id(&value)?;
                Ok(Some(value))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        validate_id(next)?;
        let lock = self.lock_file()?;
        lock.lock_exclusive()?;
        let actual = self.read_head()?;
        if actual.as_deref() != expected {
            fs2::FileExt::unlock(&lock)?;
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual,
            }
            .into());
        }

        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let temporary = self.root.join(format!(".HEAD-{}", hex::encode(random)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{next}")?;
        file.sync_all()?;
        fs::rename(&temporary, self.root.join("HEAD"))?;
        Self::sync_directory(&self.root)?;
        fs2::FileExt::unlock(&lock)?;
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid opaque object id")
    }
    Ok(())
}

const CARRIER_BRANCH: &str = "git-remote-e2ee";
const CARRIER_CHUNK_SIZE: usize = 32 * 1024 * 1024;

pub struct GitStorage {
    checkout: tempfile::TempDir,
    state: Mutex<GitStorageState>,
}

struct GitStorageState {
    base_commit: Option<String>,
}

impl GitStorage {
    pub fn open(remote: &str) -> Result<Self> {
        if remote.is_empty() {
            bail!("empty carrier Git remote")
        }
        let checkout = tempfile::Builder::new()
            .prefix("git-remote-e2ee-carrier-")
            .tempdir()?;
        git_command(
            checkout
                .path()
                .parent()
                .context("carrier tempdir has no parent")?,
            &[
                "clone",
                "--quiet",
                "--no-checkout",
                remote,
                checkout.path_str()?,
            ],
        )?;
        git_command(checkout.path(), &["config", "user.name", "git-remote-e2ee"])?;
        git_command(
            checkout.path(),
            &["config", "user.email", "git-remote-e2ee@invalid"],
        )?;

        let remote_ref = format!("refs/remotes/origin/{CARRIER_BRANCH}");
        let base_commit = git_rev_parse(checkout.path(), &remote_ref)?;
        match &base_commit {
            Some(_) => {
                git_command(
                    checkout.path(),
                    &["checkout", "--quiet", "-B", CARRIER_BRANCH, &remote_ref],
                )?;
            }
            None => {
                git_command(
                    checkout.path(),
                    &["checkout", "--quiet", "--orphan", CARRIER_BRANCH],
                )?;
            }
        }
        Ok(Self {
            checkout,
            state: Mutex::new(GitStorageState { base_commit }),
        })
    }

    fn root(&self) -> &Path {
        self.checkout.path()
    }

    fn object_directory(&self, kind: ObjectKind, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        Ok(self
            .root()
            .join("e2ee")
            .join(kind.directory())
            .join(&id[..2])
            .join(id))
    }

    fn read_object_directory(&self, directory: &Path) -> Result<Vec<u8>> {
        let mut chunks = fs::read_dir(directory)
            .with_context(|| format!("read carrier object {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        chunks.sort_by_key(|entry| entry.file_name());
        let mut result = Vec::new();
        for entry in chunks {
            if entry.file_type()?.is_file() {
                result.extend_from_slice(&fs::read(entry.path())?);
            }
        }
        Ok(result)
    }

    fn local_head(&self) -> Result<Option<String>> {
        let path = self.root().join("e2ee/HEAD");
        match fs::read_to_string(path) {
            Ok(value) => {
                let value = value.trim().to_owned();
                validate_id(&value)?;
                Ok(Some(value))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn remote_tip(&self) -> Result<Option<String>> {
        let output = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["ls-remote", "--heads", "origin"])
            .arg(format!("refs/heads/{CARRIER_BRANCH}"))
            .output()?;
        if !output.status.success() {
            bail!(
                "git ls-remote failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
        let text = String::from_utf8(output.stdout)?;
        Ok(text.split_whitespace().next().map(ToOwned::to_owned))
    }

    fn head_at_commit(&self, commit: Option<&str>) -> Result<Option<String>> {
        let Some(commit) = commit else {
            return Ok(None);
        };
        let output = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["show", &format!("{commit}:e2ee/HEAD")])
            .output()?;
        if !output.status.success() {
            return Ok(None);
        }
        let value = String::from_utf8(output.stdout)?.trim().to_owned();
        validate_id(&value)?;
        Ok(Some(value))
    }
}

trait TempDirPath {
    fn path_str(&self) -> Result<&str>;
}

impl TempDirPath for tempfile::TempDir {
    fn path_str(&self) -> Result<&str> {
        self.path()
            .to_str()
            .context("carrier checkout path is not UTF-8")
    }
}

impl Storage for GitStorage {
    fn put_object_if_absent(&self, kind: ObjectKind, id: &str, data: &[u8]) -> Result<()> {
        let directory = self.object_directory(kind, id)?;
        if directory.exists() {
            if self.read_object_directory(&directory)? != data {
                bail!("object id collision for {id}")
            }
            return Ok(());
        }
        fs::create_dir_all(&directory)?;
        for (index, chunk) in data.chunks(CARRIER_CHUNK_SIZE).enumerate() {
            fs::write(directory.join(format!("{index:08}")), chunk)?;
        }
        Ok(())
    }

    fn get_object(&self, kind: ObjectKind, id: &str) -> Result<Vec<u8>> {
        self.read_object_directory(&self.object_directory(kind, id)?)
    }

    fn read_head(&self) -> Result<Option<String>> {
        self.local_head()
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        validate_id(next)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let remote_tip = self.remote_tip()?;
        if remote_tip != state.base_commit {
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual: self.head_at_commit(remote_tip.as_deref())?,
            }
            .into());
        }
        let actual = self.local_head()?;
        if actual.as_deref() != expected {
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual,
            }
            .into());
        }

        fs::create_dir_all(self.root().join("e2ee"))?;
        fs::write(self.root().join("e2ee/HEAD"), format!("{next}\n"))?;
        git_command(self.root(), &["add", "e2ee"])?;
        git_command(
            self.root(),
            &["commit", "--quiet", "-m", "git-remote-e2ee storage update"],
        )?;
        let new_commit =
            git_rev_parse(self.root(), "HEAD")?.context("carrier commit was not created")?;
        let push = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["push", "--quiet", "origin"])
            .arg(format!("HEAD:refs/heads/{CARRIER_BRANCH}"))
            .output()?;
        if !push.status.success() {
            let latest = self.remote_tip()?;
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual: self.head_at_commit(latest.as_deref())?,
            }
            .into());
        }
        state.base_commit = Some(new_commit);
        Ok(())
    }
}

fn git_rev_parse(repo: &Path, reference: &str) -> Result<Option<String>> {
    let output = carrier_git_command()
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", reference])
        .output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else {
        Ok(None)
    }
}

fn git_command(repo: &Path, args: &[&str]) -> Result<()> {
    let output = carrier_git_command()
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn carrier_git_command() -> Command {
    let mut command = Command::new("git");
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_QUARANTINE_PATH",
    ] {
        command.env_remove(variable);
    }
    command
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::crypto::object_id;

    #[test]
    fn head_compare_and_swap_rejects_stale_writer() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(directory.path());
        let first = object_id(b"first");
        let second = object_id(b"second");
        storage.compare_and_swap_head(None, &first).unwrap();
        let error = storage.compare_and_swap_head(None, &second).unwrap_err();
        assert!(error.downcast_ref::<CasConflict>().is_some());
        assert_eq!(
            storage.read_head().unwrap().as_deref(),
            Some(first.as_str())
        );
    }

    #[test]
    fn concurrent_creators_have_exactly_one_winner() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(FilesystemStorage::new(directory.path()));
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let handles: Vec<_> = (0..writers)
            .map(|writer| {
                let storage = Arc::clone(&storage);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let candidate = object_id(format!("writer-{writer}").as_bytes());
                    barrier.wait();
                    storage
                        .compare_and_swap_head(None, &candidate)
                        .map(|_| candidate)
                })
            })
            .collect();

        let winners: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().ok())
            .collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(storage.read_head().unwrap(), Some(winners[0].clone()));
    }
}
