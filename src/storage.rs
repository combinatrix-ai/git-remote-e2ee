use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("head changed concurrently (expected {expected:?}, actual {actual:?})")]
pub struct CasConflict {
    pub expected: Option<String>,
    pub actual: Option<String>,
}

const MAX_BUFFERED_OBJECT_SIZE: u64 = 16 * 1024 * 1024;

pub trait ObjectStage: Write + Send {
    fn finish(self: Box<Self>, id: &str) -> Result<()>;
}

pub trait Storage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>>;
    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>>;

    fn put_object_if_absent(&self, kind: ObjectKind, id: &str, data: &[u8]) -> Result<()> {
        let mut stage = self.begin_object(kind)?;
        stage.write_all(data)?;
        stage.finish(id)
    }

    fn get_object(&self, kind: ObjectKind, id: &str) -> Result<Vec<u8>> {
        let mut reader = self
            .open_object(kind, id)?
            .take(MAX_BUFFERED_OBJECT_SIZE + 1);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BUFFERED_OBJECT_SIZE {
            bail!("buffered object exceeds size limit")
        }
        Ok(bytes)
    }

    fn read_head(&self) -> Result<Option<String>>;
    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug)]
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
        for name in ["objects", "manifests", "policies"] {
            let directory = self.root.join(name);
            crate::persist::create_dir_all_durable(&directory)
                .with_context(|| format!("create {}", directory.display()))?;
        }
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
}

struct FilesystemObjectStage {
    file: File,
    temporary: PathBuf,
    root: PathBuf,
    kind: ObjectKind,
    hasher: Sha256,
}

impl Write for FilesystemObjectStage {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(data)?;
        self.hasher.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl ObjectStage for FilesystemObjectStage {
    fn finish(mut self: Box<Self>, id: &str) -> Result<()> {
        validate_id(id)?;
        if hex::encode(self.hasher.clone().finalize()) != id {
            bail!("staged object hash does not match id")
        }
        self.file.flush()?;
        self.file.sync_all()?;
        crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_FILE_FLUSH);
        let target = self
            .root
            .join(self.kind.directory())
            .join(&id[..2])
            .join(id);
        let parent = target.parent().expect("object path has parent");
        crate::persist::create_dir_all_durable(parent)
            .with_context(|| format!("create {}", parent.display()))?;
        if target.exists() {
            verify_file_id(&target, id)?;
            fs::remove_file(&self.temporary)?;
            crate::persist::sync_directory(parent)
                .with_context(|| format!("sync directory {}", parent.display()))?;
            return Ok(());
        }
        match fs::hard_link(&self.temporary, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_file_id(&target, id)?;
                fs::remove_file(&self.temporary)?;
                crate::persist::sync_directory(parent)
                    .with_context(|| format!("sync directory {}", parent.display()))?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_NAME_PUBLISH);
        fs::remove_file(&self.temporary)?;
        crate::persist::sync_directory(parent)
            .with_context(|| format!("sync directory {}", parent.display()))?;
        Ok(())
    }
}

impl Drop for FilesystemObjectStage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

impl Storage for FilesystemStorage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        self.initialize()?;
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let staging = self.root.join(".staging");
        fs::create_dir_all(&staging)?;
        let temporary = staging.join(format!(".stage-{}", hex::encode(random)));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        Ok(Box::new(FilesystemObjectStage {
            file,
            temporary,
            root: self.root.clone(),
            kind,
            hasher: Sha256::new(),
        }))
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        let path = self.object_path(kind, id)?;
        Ok(Box::new(
            File::open(&path).with_context(|| format!("read {}", path.display()))?,
        ))
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
        crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_FILE_FLUSH);
        fs::rename(&temporary, self.root.join("HEAD"))?;
        crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_NAME_PUBLISH);
        crate::persist::sync_directory(&self.root)
            .with_context(|| format!("sync directory {}", self.root.display()))?;
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

fn reader_id(mut reader: impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_file_id(path: &Path, id: &str) -> Result<()> {
    if reader_id(File::open(path)?)? != id {
        bail!("object id collision for {id}")
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

struct ChunkReader {
    paths: Vec<PathBuf>,
    next: usize,
    current: Option<File>,
}

impl Read for ChunkReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(file) = &mut self.current {
                let read = file.read(output)?;
                if read != 0 {
                    return Ok(read);
                }
                self.current = None;
            }
            if self.next == self.paths.len() {
                return Ok(0);
            }
            self.current = Some(File::open(&self.paths[self.next])?);
            self.next += 1;
        }
    }
}

struct CarrierObjectStage {
    staging: PathBuf,
    root: PathBuf,
    kind: ObjectKind,
    current: Option<File>,
    chunk_index: usize,
    chunk_len: usize,
    hasher: Sha256,
}

impl CarrierObjectStage {
    fn open_chunk(&mut self) -> std::io::Result<()> {
        if self.current.is_none() {
            self.current = Some(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.staging.join(format!("{:08}", self.chunk_index)))?,
            );
            self.chunk_len = 0;
        }
        Ok(())
    }

    fn finish_chunk(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.current.take() {
            file.flush()?;
            file.sync_all()?;
            self.chunk_index += 1;
            self.chunk_len = 0;
        }
        Ok(())
    }
}

impl Write for CarrierObjectStage {
    fn write(&mut self, mut data: &[u8]) -> std::io::Result<usize> {
        let original = data.len();
        while !data.is_empty() {
            self.open_chunk()?;
            let available = CARRIER_CHUNK_SIZE - self.chunk_len;
            let take = available.min(data.len());
            self.current
                .as_mut()
                .expect("carrier chunk opened")
                .write_all(&data[..take])?;
            self.hasher.update(&data[..take]);
            self.chunk_len += take;
            data = &data[take..];
            if self.chunk_len == CARRIER_CHUNK_SIZE {
                self.finish_chunk()?;
            }
        }
        Ok(original)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(file) = &mut self.current {
            file.flush()?;
        }
        Ok(())
    }
}

impl ObjectStage for CarrierObjectStage {
    fn finish(mut self: Box<Self>, id: &str) -> Result<()> {
        validate_id(id)?;
        if hex::encode(self.hasher.clone().finalize()) != id {
            bail!("staged object hash does not match id")
        }
        self.finish_chunk()?;
        if self.chunk_index == 0 {
            bail!("cannot store an empty carrier object")
        }
        let target = self
            .root
            .join("e2ee")
            .join(self.kind.directory())
            .join(&id[..2])
            .join(id);
        if target.exists() {
            let paths = validated_chunk_paths(&target)?;
            if reader_id(ChunkReader {
                paths,
                next: 0,
                current: None,
            })? != id
            {
                bail!("object id collision for {id}")
            }
            fs::remove_dir_all(&self.staging)?;
            return Ok(());
        }
        fs::create_dir_all(target.parent().expect("carrier object path has parent"))?;
        // The fast-forward push is the compare-and-swap. This rename only
        // updates a temporary checkout and is not a filesystem durability boundary.
        fs::rename(&self.staging, target)?;
        Ok(())
    }
}

impl Drop for CarrierObjectStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.staging);
    }
}

fn validated_chunk_paths(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read carrier object {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.is_empty() {
        bail!("carrier object has no chunks")
    }
    let total = entries.len();
    let mut paths = Vec::with_capacity(total);
    for (index, entry) in entries.into_iter().enumerate() {
        if !entry.file_type()?.is_file()
            || entry.file_name().to_str() != Some(&format!("{index:08}"))
        {
            bail!("carrier object chunks are not a dense canonical sequence")
        }
        let length = entry.metadata()?.len();
        if (index + 1 < total && length != CARRIER_CHUNK_SIZE as u64)
            || (index + 1 == total && (length == 0 || length > CARRIER_CHUNK_SIZE as u64))
        {
            bail!("carrier object chunk has invalid size")
        }
        paths.push(entry.path());
    }
    Ok(paths)
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
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let staging = self.root().join(format!(".stage-{}", hex::encode(random)));
        fs::create_dir(&staging)?;
        Ok(Box::new(CarrierObjectStage {
            staging,
            root: self.root().to_path_buf(),
            kind,
            current: None,
            chunk_index: 0,
            chunk_len: 0,
            hasher: Sha256::new(),
        }))
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        let paths = validated_chunk_paths(&self.object_directory(kind, id)?)?;
        Ok(Box::new(ChunkReader {
            paths,
            next: 0,
            current: None,
        }))
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

    #[test]
    fn filesystem_object_stage_streams_and_validates_the_id() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(directory.path());
        let data = vec![0x5a; 2 * 1024 * 1024 + 3];
        let id = object_id(&data);
        let mut stage = storage.begin_object(ObjectKind::Pack).unwrap();
        for chunk in data.chunks(7777) {
            stage.write_all(chunk).unwrap();
        }
        stage.finish(&id).unwrap();
        let mut opened = storage.open_object(ObjectKind::Pack, &id).unwrap();
        let mut actual = Vec::new();
        opened.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, data);

        let mut rejected = storage.begin_object(ObjectKind::Pack).unwrap();
        rejected.write_all(b"wrong id").unwrap();
        assert!(rejected.finish(&object_id(b"something else")).is_err());
    }

    #[test]
    fn buffered_object_reads_have_a_hard_limit() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(directory.path());
        let data = vec![1_u8; MAX_BUFFERED_OBJECT_SIZE as usize + 1];
        let id = object_id(&data);
        storage
            .put_object_if_absent(ObjectKind::Pack, &id, &data)
            .unwrap();
        assert!(storage.get_object(ObjectKind::Pack, &id).is_err());
    }

    #[test]
    fn carrier_chunk_sequence_is_canonical() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("00000000"), b"first").unwrap();
        fs::write(directory.path().join("00000002"), b"gap").unwrap();
        assert!(validated_chunk_paths(directory.path()).is_err());

        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("00000000"), b"only").unwrap();
        let paths = validated_chunk_paths(directory.path()).unwrap();
        assert_eq!(
            reader_id(ChunkReader {
                paths,
                next: 0,
                current: None
            })
            .unwrap(),
            object_id(b"only")
        );

        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("00000000")).unwrap();
        assert!(validated_chunk_paths(directory.path()).is_err());
    }
}
