use std::collections::HashSet;
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

use crate::crypto::object_id;
use crate::trace;

#[derive(Debug, Error)]
#[error("head changed concurrently (expected {expected:?}, actual {actual:?})")]
pub struct CasConflict {
    pub expected: Option<String>,
    pub actual: Option<String>,
}

const MAX_BUFFERED_OBJECT_SIZE: u64 = 16 * 1024 * 1024;
const MAX_STORAGE_HEAD_BYTES: u64 = 4096;

pub trait ObjectStage: Write + Send {
    fn finish(self: Box<Self>, id: &str) -> Result<()>;
}

trait ObjectStageSink: Write + Send + Sized {
    fn publish(self, id: &str) -> Result<()>;
}

struct ValidatingObjectStage<S> {
    sink: S,
    hasher: Sha256,
}

impl<S: ObjectStageSink + 'static> ValidatingObjectStage<S> {
    fn wrap(sink: S) -> Box<dyn ObjectStage> {
        Box::new(Self {
            sink,
            hasher: Sha256::new(),
        })
    }
}

impl<S: ObjectStageSink> Write for ValidatingObjectStage<S> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = self.sink.write(data)?;
        self.hasher.update(&data[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

impl<S: ObjectStageSink> ObjectStage for ValidatingObjectStage<S> {
    fn finish(self: Box<Self>, id: &str) -> Result<()> {
        validate_id(id)?;
        let Self { sink, hasher } = *self;
        if hex::encode(hasher.finalize()) != id {
            bail!("staged object hash does not match id")
        }
        sink.publish(id)
    }
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

    fn observe_head(&self) -> Result<HeadObservation> {
        let head_id = self.read_head()?;
        let bytes = head_id.as_deref().unwrap_or_default().as_bytes().to_vec();
        Ok(HeadObservation {
            head_id,
            token: bytes.clone(),
            head_bytes: Some(bytes),
        })
    }

    fn compare_and_swap_observed_head(&self, observed: &HeadObservation, next: &str) -> Result<()> {
        self.compare_and_swap_head(observed.head_id.as_deref(), next)
    }

    fn recovery_history(
        &self,
        _max_commits: usize,
        _max_manifest_bytes: u64,
    ) -> Result<Option<RecoveryHistory>> {
        Ok(None)
    }

    fn restore_historical_object(&self, _kind: ObjectKind, _id: &str) -> Result<bool> {
        Ok(false)
    }

    fn prepare_recovery(&self, _manifest_ids: &[String], _pack_ids: &[String]) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HeadObservation {
    pub head_id: Option<String>,
    pub token: Vec<u8>,
    pub head_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RecoveryCommit {
    pub commit_id: String,
    pub head_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RecoveryHistory {
    pub commits: Vec<RecoveryCommit>,
    pub manifests: std::collections::BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub enum ObjectKind {
    Pack,
    Manifest,
}

impl ObjectKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Pack => "objects",
            Self::Manifest => "manifests",
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
        for name in ["objects", "manifests"] {
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
}

impl Write for FilesystemObjectStage {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.file.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl ObjectStageSink for FilesystemObjectStage {
    fn publish(mut self, id: &str) -> Result<()> {
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
        Ok(ValidatingObjectStage::wrap(FilesystemObjectStage {
            file,
            temporary,
            root: self.root.clone(),
            kind,
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

    fn observe_head(&self) -> Result<HeadObservation> {
        let head_bytes = read_bounded_head_file(&self.root.join("HEAD"))?;
        let head_id = head_bytes.as_deref().and_then(|bytes| {
            std::str::from_utf8(bytes)
                .ok()
                .map(str::trim)
                .filter(|value| validate_id(value).is_ok())
                .map(ToOwned::to_owned)
        });
        Ok(HeadObservation {
            head_id,
            token: head_bytes.clone().unwrap_or_default(),
            head_bytes,
        })
    }

    fn compare_and_swap_observed_head(&self, observed: &HeadObservation, next: &str) -> Result<()> {
        validate_id(next)?;
        let lock = self.lock_file()?;
        lock.lock_exclusive()?;
        let actual = match fs::read(self.root.join("HEAD")) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                fs2::FileExt::unlock(&lock)?;
                return Err(error.into());
            }
        };
        if actual != observed.head_bytes {
            let actual_id = actual.as_deref().and_then(|bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .map(str::trim)
                    .filter(|value| validate_id(value).is_ok())
                    .map(ToOwned::to_owned)
            });
            fs2::FileExt::unlock(&lock)?;
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: actual_id,
            }
            .into());
        }

        write_filesystem_head_locked(&self.root, next)?;
        fs2::FileExt::unlock(&lock)?;
        Ok(())
    }
}

fn write_filesystem_head_locked(root: &Path, next: &str) -> Result<()> {
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = root.join(format!(".HEAD-{}", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    writeln!(file, "{next}")?;
    file.sync_all()?;
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_FILE_FLUSH);
    fs::rename(&temporary, root.join("HEAD"))?;
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_NAME_PUBLISH);
    crate::persist::sync_directory(root)
        .with_context(|| format!("sync directory {}", root.display()))?;
    Ok(())
}

fn read_bounded_head_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_STORAGE_HEAD_BYTES {
        bail!("recovery outer-head byte budget exhausted")
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
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
const CARRIER_CACHE_ENV: &str = "GIT_REMOTE_E2EE_CACHE_DIR";
const CARRIER_CACHE_FETCH_REF: &str = "refs/heads/git-remote-e2ee";
const MAX_RECOVERY_OUTER_COMMITS: usize = 2048;

pub struct GitStorage {
    checkout: tempfile::TempDir,
    remote: String,
    state: Mutex<GitStorageState>,
}

struct GitStorageState {
    base_commit: Option<String>,
}

struct ChunkReader {
    paths: Vec<PathBuf>,
    next: usize,
    current: Option<File>,
    trace: trace::Io,
}

impl Read for ChunkReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let started = self.trace.is_active().then(std::time::Instant::now);
        loop {
            if let Some(file) = &mut self.current {
                let read = file.read(output)?;
                if read != 0 {
                    self.trace.record(
                        read,
                        started.map_or(0, |started| started.elapsed().as_nanos()),
                    );
                    return Ok(read);
                }
                self.current = None;
            }
            if self.next == self.paths.len() {
                self.trace
                    .record(0, started.map_or(0, |started| started.elapsed().as_nanos()));
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

impl ObjectStageSink for CarrierObjectStage {
    fn publish(mut self, id: &str) -> Result<()> {
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
                trace: trace::Io::new("carrier_object_read"),
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

        let lock_timer = trace::Span::new("carrier_cache_lock");
        let mut cache = CarrierCache::lock(remote)?;
        drop(lock_timer);
        let fetch_timer = trace::Span::new("carrier_cache_fetch");
        let mut base_commit = cache.refresh(remote)?;
        drop(fetch_timer);
        let mut checkout = tempfile::Builder::new()
            .prefix("git-remote-e2ee-carrier-")
            .tempdir()?;
        let checkout_timer = trace::Span::new("carrier_checkout_create");
        if let Err(error) =
            create_carrier_checkout(checkout.path(), &cache.path, remote, &base_commit)
        {
            if !cache.is_corrupt()? {
                return Err(error).context("create carrier checkout");
            }
            drop(checkout);
            cache.rebuild()?;
            base_commit = cache.refresh(remote)?;
            checkout = tempfile::Builder::new()
                .prefix("git-remote-e2ee-carrier-")
                .tempdir()?;
            create_carrier_checkout(checkout.path(), &cache.path, remote, &base_commit)
                .context("create carrier checkout after rebuilding corrupt cache")?;
        }
        drop(checkout_timer);
        drop(cache);

        Ok(Self {
            checkout,
            remote: remote.to_owned(),
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

    fn local_head_bytes(&self) -> Result<Option<Vec<u8>>> {
        read_bounded_head_file(&self.root().join("e2ee/HEAD"))
    }

    fn refresh_remote(&self) -> Result<Option<String>> {
        CarrierCache::lock(&self.remote)?.refresh(&self.remote)
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

    fn head_bytes_at_commit(&self, commit: &str) -> Result<Option<Vec<u8>>> {
        let object = format!("{commit}:e2ee/HEAD");
        let size = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["cat-file", "-s", &object])
            .output()?;
        if !size.status.success() {
            return Ok(None);
        }
        let size = String::from_utf8(size.stdout)?.trim().parse::<u64>()?;
        if size > MAX_STORAGE_HEAD_BYTES {
            bail!("recovery outer-head byte budget exhausted")
        }
        let output = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["show", &object])
            .output()?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            Ok(None)
        }
    }

    fn commit_history(&self, limit: usize) -> Result<Vec<String>> {
        let maximum = limit.saturating_add(1).to_string();
        let output = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args([
                "rev-list",
                "--parents",
                &format!("--max-count={maximum}"),
                "HEAD",
            ])
            .output()?;
        ensure_git_success(&output, "git rev-list carrier history")?;
        // Every publication is a single-parent fast-forward commit, so
        // legitimate carrier history is linear. A merge can only come from a
        // storage-level writer and can hide a legitimate state behind a
        // non-first parent, so recovery refuses to interpret such history.
        let mut commits = Vec::new();
        for line in String::from_utf8(output.stdout)?.lines() {
            let mut fields = line.split_ascii_whitespace();
            let commit = fields.next().context("parse carrier history entry")?;
            if fields.count() > 1 {
                bail!(
                    "carrier history contains merge commit {commit}; recovery requires linear carrier history and cannot rule out a hidden legitimate state"
                )
            }
            commits.push(commit.to_owned());
        }
        Ok(commits)
    }

    fn chunk_entries_at(
        &self,
        commit: &str,
        kind: ObjectKind,
        id: &str,
    ) -> Result<Option<Vec<(String, String)>>> {
        validate_id(id)?;
        let directory = format!("e2ee/{}/{}/{id}", kind.directory(), &id[..2]);
        let output = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["ls-tree", "-r", "-z", commit, "--", &directory])
            .output()?;
        ensure_git_success(&output, "git ls-tree historical carrier object")?;
        if output.stdout.is_empty() {
            return Ok(None);
        }
        if output.stdout.len() > 8 * 1024 * 1024 {
            bail!("carrier recovery object listing exceeds its size budget")
        }
        let mut chunks = Vec::new();
        for entry in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let tab = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .context("parse historical carrier tree entry")?;
            let (metadata, path) = (&entry[..tab], &entry[tab + 1..]);
            let metadata = std::str::from_utf8(metadata)?;
            let path = std::str::from_utf8(path)?.to_owned();
            let mut fields = metadata.split_ascii_whitespace();
            if fields.next() != Some("100644") || fields.next() != Some("blob") {
                bail!("historical carrier object contains a non-regular blob")
            }
            let blob_id = fields.next().context("historical carrier blob has no id")?;
            if fields.next().is_some() || !path.starts_with(&format!("{directory}/")) {
                bail!("unexpected historical carrier object path")
            }
            chunks.push((path, blob_id.to_owned()));
        }
        chunks.sort_by(|left, right| left.0.cmp(&right.0));
        if chunks.is_empty() || chunks.len() > 4096 {
            bail!("historical carrier object has an invalid chunk count")
        }
        for (index, (path, _)) in chunks.iter().enumerate() {
            let expected = format!("{directory}/{index:08}");
            if path != &expected {
                bail!("historical carrier object chunks are not a dense canonical sequence")
            }
        }
        Ok(Some(chunks))
    }

    fn object_at_commit(
        &self,
        commit: &str,
        kind: ObjectKind,
        id: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(chunks) = self.chunk_entries_at(commit, kind, id)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        for (index, (path, _)) in chunks.iter().enumerate() {
            let output = carrier_git_command()
                .arg("-C")
                .arg(self.root())
                .args(["show", &format!("{commit}:{path}")])
                .output()?;
            ensure_git_success(&output, "git show historical carrier object")?;
            let length = output.stdout.len();
            if (index + 1 < chunks.len() && length != CARRIER_CHUNK_SIZE)
                || (index + 1 == chunks.len() && (length == 0 || length > CARRIER_CHUNK_SIZE))
            {
                bail!("historical carrier object chunk has invalid size")
            }
            let next_length = (bytes.len() as u64)
                .checked_add(length as u64)
                .context("historical carrier object size overflow")?;
            if next_length > max_bytes {
                bail!("carrier recovery manifest byte budget exhausted")
            }
            bytes.extend_from_slice(&output.stdout);
        }
        if object_id(&bytes) != id {
            bail!("historical carrier object content id mismatch")
        }
        Ok(Some(bytes))
    }

    fn restore_object_at(&self, commit: &str, kind: ObjectKind, id: &str) -> Result<bool> {
        let Some(chunks) = self.chunk_entries_at(commit, kind, id)? else {
            return Ok(false);
        };
        let staging = tempfile::Builder::new()
            .prefix("git-remote-e2ee-restore-")
            .tempdir_in(self.root())?;
        let object_dir = staging.path().join("object");
        fs::create_dir(&object_dir)?;
        let mut hasher = Sha256::new();
        for (index, (path, _)) in chunks.iter().enumerate() {
            let output = carrier_git_command()
                .arg("-C")
                .arg(self.root())
                .args(["show", &format!("{commit}:{path}")])
                .output()?;
            ensure_git_success(&output, "git show historical carrier object")?;
            let length = output.stdout.len();
            if (index + 1 < chunks.len() && length != CARRIER_CHUNK_SIZE)
                || (index + 1 == chunks.len() && (length == 0 || length > CARRIER_CHUNK_SIZE))
            {
                bail!("historical carrier object chunk has invalid size")
            }
            hasher.update(&output.stdout);
            let chunk_path = object_dir.join(format!("{index:08}"));
            let mut file = File::create(chunk_path)?;
            file.write_all(&output.stdout)?;
            file.sync_all()?;
        }
        if hex::encode(hasher.finalize()) != id {
            bail!("historical carrier object content id mismatch")
        }
        let target = self.object_directory(kind, id)?;
        if target.exists() {
            fs::remove_dir_all(&target)?;
        }
        fs::create_dir_all(
            target
                .parent()
                .context("carrier object path has no parent")?,
        )?;
        fs::rename(object_dir, target)?;
        Ok(true)
    }

    fn publish_checkout_head(&self, next: &str, expected: Option<String>) -> Result<()> {
        fs::create_dir_all(self.root().join("e2ee"))?;
        fs::write(self.root().join("e2ee/HEAD"), format!("{next}\n"))?;
        let add_timer = trace::Span::new("carrier_git_add");
        git_command(self.root(), &["add", "e2ee"])?;
        drop(add_timer);
        let commit_timer = trace::Span::new("carrier_git_commit");
        git_command(
            self.root(),
            &["commit", "--quiet", "-m", "git-remote-e2ee storage update"],
        )?;
        drop(commit_timer);
        let push_timer = trace::Span::new("carrier_git_push");
        let push = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["push", "--quiet", "origin"])
            .arg(format!("HEAD:refs/heads/{CARRIER_BRANCH}"))
            .output()?;
        if !push.status.success() {
            let latest = self.refresh_remote()?;
            return Err(CasConflict {
                expected,
                actual: self.head_at_commit(latest.as_deref())?,
            }
            .into());
        }
        drop(push_timer);
        Ok(())
    }
}

impl Storage for GitStorage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let staging = self.root().join(format!(".stage-{}", hex::encode(random)));
        fs::create_dir(&staging)?;
        Ok(ValidatingObjectStage::wrap(CarrierObjectStage {
            staging,
            root: self.root().to_path_buf(),
            kind,
            current: None,
            chunk_index: 0,
            chunk_len: 0,
        }))
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        let paths = validated_chunk_paths(&self.object_directory(kind, id)?)?;
        Ok(Box::new(ChunkReader {
            paths,
            next: 0,
            current: None,
            trace: trace::Io::new("carrier_object_read"),
        }))
    }

    fn read_head(&self) -> Result<Option<String>> {
        // `open` refreshed the remote before constructing this checkout; CAS
        // refreshes again before trusting this snapshot for a write.
        self.local_head()
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        validate_id(next)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let refresh_timer = trace::Span::new("carrier_cas_refresh");
        let remote_tip = self.refresh_remote()?;
        drop(refresh_timer);
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
        let add_timer = trace::Span::new("carrier_git_add");
        git_command(self.root(), &["add", "e2ee"])?;
        drop(add_timer);
        let commit_timer = trace::Span::new("carrier_git_commit");
        git_command(
            self.root(),
            &["commit", "--quiet", "-m", "git-remote-e2ee storage update"],
        )?;
        drop(commit_timer);
        let new_commit =
            git_rev_parse(self.root(), "HEAD")?.context("carrier commit was not created")?;
        let push_timer = trace::Span::new("carrier_git_push");
        let push = carrier_git_command()
            .arg("-C")
            .arg(self.root())
            .args(["push", "--quiet", "origin"])
            .arg(format!("HEAD:refs/heads/{CARRIER_BRANCH}"))
            .output()?;
        if !push.status.success() {
            let latest = self.refresh_remote()?;
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual: self.head_at_commit(latest.as_deref())?,
            }
            .into());
        }
        drop(push_timer);
        state.base_commit = Some(new_commit);
        Ok(())
    }

    fn observe_head(&self) -> Result<HeadObservation> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let head_bytes = self.local_head_bytes()?;
        let head_id = head_bytes.as_deref().and_then(|bytes| {
            std::str::from_utf8(bytes)
                .ok()
                .map(str::trim)
                .filter(|value| validate_id(value).is_ok())
                .map(ToOwned::to_owned)
        });
        Ok(HeadObservation {
            head_id,
            token: state
                .base_commit
                .as_deref()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
            head_bytes,
        })
    }

    fn compare_and_swap_observed_head(&self, observed: &HeadObservation, next: &str) -> Result<()> {
        validate_id(next)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let expected_tip = state.base_commit.clone();
        if observed.token != expected_tip.as_deref().unwrap_or_default().as_bytes() {
            bail!("recovery storage token does not match the opened carrier tip")
        }
        let remote_tip = self.refresh_remote()?;
        if remote_tip != expected_tip {
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: self.head_at_commit(remote_tip.as_deref())?,
            }
            .into());
        }
        let actual_bytes = self.local_head_bytes()?;
        if actual_bytes != observed.head_bytes {
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: actual_bytes.as_deref().and_then(|bytes| {
                    std::str::from_utf8(bytes)
                        .ok()
                        .map(str::trim)
                        .filter(|value| validate_id(value).is_ok())
                        .map(ToOwned::to_owned)
                }),
            }
            .into());
        }
        self.publish_checkout_head(next, observed.head_id.clone())?;
        let new_commit =
            git_rev_parse(self.root(), "HEAD")?.context("carrier commit was not created")?;
        state.base_commit = Some(new_commit);
        Ok(())
    }

    fn recovery_history(
        &self,
        max_commits: usize,
        max_manifest_bytes: u64,
    ) -> Result<Option<RecoveryHistory>> {
        let commits = self.commit_history(max_commits)?;
        if commits.len() > max_commits {
            bail!("carrier recovery outer-commit budget exhausted")
        }
        let mut history = RecoveryHistory::default();
        let mut total_bytes = 0_u64;
        for commit_id in commits {
            let head_id = self
                .head_bytes_at_commit(&commit_id)?
                .as_deref()
                .and_then(|bytes| {
                    std::str::from_utf8(bytes)
                        .ok()
                        .map(str::trim)
                        .filter(|value| validate_id(value).is_ok())
                        .map(ToOwned::to_owned)
                });
            if let Some(id) = &head_id
                && !history.manifests.contains_key(id)
            {
                let remaining = max_manifest_bytes.saturating_sub(total_bytes);
                if let Some(bytes) =
                    self.object_at_commit(&commit_id, ObjectKind::Manifest, id, remaining)?
                {
                    total_bytes = total_bytes
                        .checked_add(bytes.len() as u64)
                        .context("carrier recovery manifest byte count overflow")?;
                    if total_bytes > max_manifest_bytes {
                        bail!("carrier recovery manifest byte budget exhausted")
                    }
                    history.manifests.insert(id.clone(), bytes);
                }
            }
            history.commits.push(RecoveryCommit { commit_id, head_id });
        }
        Ok(Some(history))
    }

    fn restore_historical_object(&self, kind: ObjectKind, id: &str) -> Result<bool> {
        let commits = self.commit_history(MAX_RECOVERY_OUTER_COMMITS)?;
        if commits.len() > MAX_RECOVERY_OUTER_COMMITS {
            bail!("carrier recovery outer-commit budget exhausted")
        }
        for commit in commits {
            if self.restore_object_at(&commit, kind, id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn prepare_recovery(&self, manifest_ids: &[String], pack_ids: &[String]) -> Result<()> {
        retain_carrier_objects(
            &self.root().join("e2ee/manifests"),
            &manifest_ids.iter().map(String::as_str).collect(),
        )?;
        retain_carrier_objects(
            &self.root().join("e2ee/objects"),
            &pack_ids.iter().map(String::as_str).collect(),
        )?;
        Ok(())
    }
}

fn retain_carrier_objects(root: &Path, keep: &HashSet<&str>) -> Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for prefix in entries {
        if !prefix.file_type()?.is_dir() {
            fs::remove_file(prefix.path())?;
            continue;
        }
        let objects = fs::read_dir(prefix.path())?.collect::<std::io::Result<Vec<_>>>()?;
        for object in objects {
            let id = object.file_name();
            if id.to_str().is_none_or(|id| !keep.contains(id)) {
                if object.file_type()?.is_dir() {
                    fs::remove_dir_all(object.path())?;
                } else {
                    fs::remove_file(object.path())?;
                }
            }
        }
        if fs::read_dir(prefix.path())?.next().is_none() {
            fs::remove_dir(prefix.path())?;
        }
    }
    Ok(())
}

struct CarrierCache {
    remote_dir: PathBuf,
    path: PathBuf,
    _lock: File,
}

impl CarrierCache {
    fn lock(remote: &str) -> Result<Self> {
        let normalized = normalize_carrier_remote(remote)?;
        let hash = hex::encode(Sha256::digest(normalized.as_bytes()));
        let root = carrier_cache_root()?;
        fs::create_dir_all(&root)
            .with_context(|| format!("create carrier cache directory {}", root.display()))?;
        let root = fs::canonicalize(&root)?;
        let lock_path = root.join(format!(".{hash}.lock"));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open carrier cache lock {}", lock_path.display()))?;
        let wait_timer = trace::Span::new("carrier_cache_lock_wait");
        lock.lock_exclusive()
            .with_context(|| format!("lock carrier cache {}", lock_path.display()))?;
        drop(wait_timer);
        let remote_dir = root.join(&hash);
        Ok(Self {
            remote_dir,
            path: PathBuf::new(),
            _lock: lock,
        })
    }

    fn refresh(&mut self, remote: &str) -> Result<Option<String>> {
        let initialize_timer = trace::Span::new("carrier_cache_initialize");
        self.ensure_initialized()?;
        drop(initialize_timer);
        let fetch_timer = trace::Span::new("carrier_cache_fetch_remote");
        match fetch_carrier_branch(&self.path, remote) {
            Ok(tip) => {
                drop(fetch_timer);
                Ok(tip)
            }
            Err(fetch_error) if self.is_corrupt()? => {
                self.rebuild()?;
                let result = fetch_carrier_branch(&self.path, remote).with_context(|| {
                    format!(
                        "fetch carrier branch after rebuilding corrupt cache (initial fetch failed: {fetch_error:#})"
                    )
                });
                drop(fetch_timer);
                result
            }
            Err(fetch_error) => {
                drop(fetch_timer);
                Err(fetch_error)
            }
        }
    }

    fn ensure_initialized(&mut self) -> Result<()> {
        fs::create_dir_all(&self.remote_dir).with_context(|| {
            format!(
                "create per-remote carrier cache {}",
                self.remote_dir.display()
            )
        })?;
        let current = self.remote_dir.join("current");
        let generation = fs::read_to_string(&current)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| valid_cache_generation(value));
        if let Some(generation) = generation {
            self.path = self.remote_dir.join(generation);
        }
        let usable = !self.path.as_os_str().is_empty()
            && self.path.exists()
            && cache_git_output(&self.path, &["rev-parse", "--is-bare-repository"]).is_ok_and(
                |output| {
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).trim() == "true"
                },
            );
        if !usable {
            self.initialize_generation()?;
        }
        if configure_cache(&self.path).is_err() {
            self.rebuild()?;
        }
        Ok(())
    }

    fn initialize_generation(&mut self) -> Result<()> {
        fs::create_dir_all(&self.remote_dir)?;
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let generation = format!("objects-{}-{}", std::process::id(), hex::encode(random));
        self.path = self.remote_dir.join(generation);
        let output = carrier_git_command()
            .args(["init", "--bare", "--quiet"])
            .arg(&self.path)
            .output()?;
        ensure_git_success(&output, "git init --bare carrier cache")?;
        configure_cache(&self.path)?;
        cache_git_command(
            &self.path,
            &["symbolic-ref", "HEAD", CARRIER_CACHE_FETCH_REF],
        )?;
        self.publish_current()
    }

    fn is_corrupt(&self) -> Result<bool> {
        let output = cache_git_output(&self.path, &["fsck", "--full"])?;
        Ok(!output.status.success())
    }

    fn rebuild(&mut self) -> Result<()> {
        // Existing temporary checkouts may still borrow the previous object
        // directory. Keep that generation intact and publish a fresh one.
        self.initialize_generation()
    }

    fn publish_current(&self) -> Result<()> {
        let generation = self
            .path
            .file_name()
            .context("carrier cache generation has no name")?;
        let generation = generation
            .to_str()
            .context("carrier cache generation name is not UTF-8")?;
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let temporary = self.remote_dir.join(format!(
            ".current-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        writeln!(file, "{generation}")?;
        file.sync_all()?;
        let current = self.remote_dir.join("current");
        if current.exists() {
            fs::remove_file(&current)?;
        }
        fs::rename(&temporary, &current)?;
        Ok(())
    }
}

fn valid_cache_generation(value: &str) -> bool {
    value.starts_with("objects-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn carrier_cache_root() -> Result<PathBuf> {
    if let Some(override_dir) = std::env::var_os(CARRIER_CACHE_ENV) {
        if override_dir.is_empty() {
            bail!("{CARRIER_CACHE_ENV} must not be empty")
        }
        return Ok(PathBuf::from(override_dir));
    }
    let cache_home = match std::env::var_os("XDG_CACHE_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            std::env::var_os("HOME").context("HOME is unset and XDG_CACHE_HOME is unset")?,
        )
        .join(".cache"),
    };
    Ok(cache_home.join("git-remote-e2ee").join("carrier"))
}

fn normalize_carrier_remote(remote: &str) -> Result<String> {
    if remote.trim().is_empty() {
        bail!("empty carrier Git remote")
    }
    if remote.contains("://") {
        return Ok(remote.trim().trim_end_matches('/').to_owned());
    }
    if remote == remote.trim()
        && let Some((host, path)) = remote.split_once(':')
        && !host.is_empty()
        && !host.contains('/')
        && !host.contains('\\')
        && !(host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic())
        && !remote.starts_with("./")
        && !remote.starts_with("../")
        && !remote.starts_with('/')
    {
        return Ok(format!("{host}:{}", path.trim_end_matches('/')));
    }

    let path = Path::new(remote);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    match fs::canonicalize(&absolute) {
        Ok(path) => Ok(path.to_string_lossy().into_owned()),
        Err(_) => Ok(lexically_normalize(&absolute)
            .to_string_lossy()
            .into_owned()),
    }
}

fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn configure_cache(cache: &Path) -> Result<()> {
    cache_git_command(cache, &["config", "gc.auto", "0"])?;
    cache_git_command(cache, &["config", "maintenance.auto", "false"])?;
    Ok(())
}

fn fetch_carrier_branch(cache: &Path, remote: &str) -> Result<Option<String>> {
    let refspec = format!("+refs/heads/{CARRIER_BRANCH}:{CARRIER_CACHE_FETCH_REF}");
    let fetch = cache_git_output(cache, &["fetch", "--quiet", "--no-tags", remote, &refspec])?;
    if fetch.status.success() {
        return git_rev_parse(cache, CARRIER_CACHE_FETCH_REF);
    }

    let ls_remote = cache_git_output(
        cache,
        &["ls-remote", "--heads", remote, CARRIER_CACHE_FETCH_REF],
    )?;
    ensure_git_success(&ls_remote, "git ls-remote carrier branch")?;
    if String::from_utf8_lossy(&ls_remote.stdout).trim().is_empty() {
        let delete = cache_git_output(cache, &["update-ref", "-d", CARRIER_CACHE_FETCH_REF])?;
        ensure_git_success(&delete, "git update-ref delete missing carrier branch")?;
        return Ok(None);
    }
    ensure_git_success(&fetch, "git fetch carrier branch")?;
    unreachable!("failed git fetch must return an error")
}

fn create_carrier_checkout(
    checkout: &Path,
    cache: &Path,
    remote: &str,
    base_commit: &Option<String>,
) -> Result<()> {
    let _timer = trace::Span::new("carrier_checkout_git_setup");
    let output = carrier_git_command()
        .arg("-C")
        .arg(checkout)
        .args(["init", "--quiet"])
        .output()?;
    ensure_git_success(&output, "git init carrier checkout")?;
    let cache_objects = cache.join("objects");
    let cache_objects = cache_objects
        .to_str()
        .context("carrier cache object path is not UTF-8")?;
    if cache_objects.contains('\n') {
        bail!("carrier cache object path contains a newline")
    }
    fs::write(
        checkout.join(".git/objects/info/alternates"),
        format!("{cache_objects}\n"),
    )?;
    git_command(checkout, &["config", "gc.auto", "0"])?;
    git_command(checkout, &["config", "maintenance.auto", "false"])?;
    git_command(checkout, &["config", "user.name", "git-remote-e2ee"])?;
    git_command(
        checkout,
        &["config", "user.email", "git-remote-e2ee@invalid"],
    )?;
    git_command(checkout, &["remote", "add", "origin", remote])?;

    let remote_ref = format!("refs/remotes/origin/{CARRIER_BRANCH}");
    match base_commit {
        Some(commit) => {
            git_command(checkout, &["update-ref", &remote_ref, commit])?;
            git_command(
                checkout,
                &["checkout", "--quiet", "-B", CARRIER_BRANCH, &remote_ref],
            )?;
        }
        None => {
            git_command(
                checkout,
                &["checkout", "--quiet", "--orphan", CARRIER_BRANCH],
            )?;
        }
    }
    Ok(())
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

fn cache_git_command(cache: &Path, args: &[&str]) -> Result<()> {
    let output = cache_git_output(cache, args)?;
    ensure_git_success(&output, &format!("git {}", args.join(" ")))
}

fn cache_git_output(cache: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(carrier_git_command()
        .arg("--git-dir")
        .arg(cache)
        .args(args)
        .output()?)
}

fn ensure_git_success(output: &std::process::Output, action: &str) -> Result<()> {
    if !output.status.success() {
        bail!(
            "{action} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::crypto::object_id;

    struct PartialWriteSink {
        published: Arc<AtomicBool>,
    }

    impl Write for PartialWriteSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            Ok(data.len().min(3))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ObjectStageSink for PartialWriteSink {
        fn publish(self, _id: &str) -> Result<()> {
            self.published.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn object_stage_validates_all_written_bytes_before_publishing() {
        let data = b"partial writes must all contribute to the staged object hash";
        let published = Arc::new(AtomicBool::new(false));
        let mut stage = ValidatingObjectStage::wrap(PartialWriteSink {
            published: Arc::clone(&published),
        });
        stage.write_all(data).unwrap();
        stage.finish(&object_id(data)).unwrap();
        assert!(published.load(Ordering::Relaxed));

        let published = Arc::new(AtomicBool::new(false));
        let mut stage = ValidatingObjectStage::wrap(PartialWriteSink {
            published: Arc::clone(&published),
        });
        stage.write_all(data).unwrap();
        assert!(stage.finish(&object_id(b"different bytes")).is_err());
        assert!(!published.load(Ordering::Relaxed));
    }

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
                current: None,
                trace: trace::Io::new("carrier_object_read"),
            })
            .unwrap(),
            object_id(b"only")
        );

        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("00000000")).unwrap();
        assert!(validated_chunk_paths(directory.path()).is_err());
    }
}
