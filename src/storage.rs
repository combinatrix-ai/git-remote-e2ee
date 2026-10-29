use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bounded::{self, Bounded, Opened};
use crate::catfile::{BatchHeader, CatFile, GitObjectType};
use crate::error::{BudgetExhausted, ObjectUnavailable};
use crate::gitcmd::{self, GitRepository};
use crate::refname;
use crate::trace;

#[derive(Debug, Error)]
#[error("head changed concurrently (expected {expected:?}, actual {actual:?})")]
pub struct CasConflict {
    pub expected: Option<String>,
    pub actual: Option<String>,
}

/// Storage holds content this tool did not write where a genesis head would
/// go. Returned before anything is written.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StorageOccupied(pub String);

// The size contract every writer enforces before publication and every
// reader enforces before allocating, so nothing published is unreadable.
pub const MAX_HEAD_BYTES: u64 = 4096;
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const CARRIER_CHUNK_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_CHUNKS_PER_OBJECT: u64 = 4096;
pub const MAX_OBJECT_BYTES: u64 = CARRIER_CHUNK_BYTES * MAX_CHUNKS_PER_OBJECT;

pub trait ObjectStage: Write + Send {
    fn finish(self: Box<Self>, id: &str) -> Result<()>;
}

trait ObjectStageSink: Write + Send + Sized {
    fn publish(self, id: &str) -> Result<()>;
}

struct ValidatingObjectStage<S> {
    sink: S,
    hasher: Sha256,
    kind: ObjectKind,
    written: u64,
}

impl<S: ObjectStageSink + 'static> ValidatingObjectStage<S> {
    fn wrap(sink: S, kind: ObjectKind) -> Box<dyn ObjectStage> {
        Box::new(Self {
            sink,
            hasher: Sha256::new(),
            kind,
            written: 0,
        })
    }
}

impl<S: ObjectStageSink> Write for ValidatingObjectStage<S> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let limit = self.kind.max_bytes();
        if self.written.saturating_add(data.len() as u64) > limit {
            return Err(std::io::Error::other(format!(
                "{} object exceeds the {limit}-byte maximum that readers accept; splitting larger objects is not supported",
                self.kind.name()
            )));
        }
        let written = self.sink.write(data)?;
        self.hasher.update(&data[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

impl<S: ObjectStageSink> ObjectStage for ValidatingObjectStage<S> {
    fn finish(self: Box<Self>, id: &str) -> Result<()> {
        validate_id(id)?;
        let Self { sink, hasher, .. } = *self;
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

    /// Buffers a whole object; the bound is the manifest limit, since
    /// manifests are the objects read this way.
    fn get_object(&self, kind: ObjectKind, id: &str) -> Result<Vec<u8>> {
        let mut reader = self.open_object(kind, id)?.take(MAX_MANIFEST_BYTES + 1);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("buffered object exceeds size limit")
        }
        Ok(bytes)
    }

    fn read_head(&self) -> Result<Option<String>>;

    /// Replaces a cached view of storage with the current one and reports
    /// whether the head may have changed. Backends that read live need not.
    fn refresh(&self) -> Result<bool> {
        Ok(false)
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()>;

    fn observe_head(&self) -> Result<HeadObservation> {
        let head_id = self.read_head()?;
        let bytes = head_id.as_deref().unwrap_or_default().as_bytes().to_vec();
        Ok(HeadObservation {
            head_id,
            token: bytes.clone(),
            head: Some(StoredHead::Bytes(bytes)),
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

    /// Restores a stored copy of `id` from storage history, reading at most
    /// `max_bytes` across every copy it tries.
    fn restore_historical_object(
        &self,
        _kind: ObjectKind,
        _id: &str,
        _max_bytes: u64,
    ) -> Result<bool> {
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
    /// What storage holds where HEAD belongs; `None` when nothing is there.
    pub head: Option<StoredHead>,
}

/// The contents of storage HEAD. Only `Bytes` can name a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredHead {
    Bytes(Vec<u8>),
    /// A symbolic link, FIFO, directory, or other non-regular entry.
    NotRegular,
    /// Longer than `MAX_HEAD_BYTES`; never read.
    Oversized,
}

impl StoredHead {
    fn from_bounded(bounded: Bounded) -> Option<Self> {
        match bounded {
            Bounded::Absent => None,
            Bounded::Within(bytes) => Some(Self::Bytes(bytes)),
            Bounded::Oversized => Some(Self::Oversized),
            Bounded::NotRegular => Some(Self::NotRegular),
        }
    }

    pub fn head_id(&self) -> Option<String> {
        let Self::Bytes(bytes) = self else {
            return None;
        };
        let value = std::str::from_utf8(bytes).ok()?.trim();
        validate_id(value).ok()?;
        Some(value.to_owned())
    }

    /// The manifest ID, or why this HEAD names none.
    pub fn parse(&self) -> Result<String> {
        match self {
            Self::Bytes(_) => self
                .head_id()
                .context("storage HEAD is not a valid head: it does not name a manifest object ID"),
            Self::NotRegular => bail!("storage HEAD is not a valid head: it is not a regular file"),
            Self::Oversized => {
                bail!("storage HEAD is not a valid head: it exceeds {MAX_HEAD_BYTES} bytes")
            }
        }
    }

    /// Bytes that identify this observation in rejected-head evidence.
    pub fn evidence(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::NotRegular => b"storage HEAD is not a regular file",
            Self::Oversized => b"storage HEAD is oversized",
        }
    }
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

/// The storage layout version this build reads and writes.
const STORAGE_FORMAT: &[u8] = b"git-remote-e2ee storage 6\n";
const STORAGE_FORMAT_PREFIX: &str = "git-remote-e2ee storage ";
const MAX_STORAGE_FORMAT_BYTES: u64 = 256;

/// Plaintext notice at the storage root. It discloses nothing beyond the
/// fact that the storage holds a git-remote-e2ee repository.
fn storage_readme(subject: &str) -> String {
    format!(
        "# Encrypted Git repository

{subject} holds an end-to-end encrypted Git repository managed by
git-remote-e2ee (https://github.com/combinatrix-ai/git-remote-e2ee).
Its contents are ciphertext. Do not edit, rename, or delete files here.

To clone it, install git-remote-e2ee and run:

    git -c e2ee.key=<your device key> clone e2ee::<this repository's URL>
"
    )
}

/// `FORMAT` is unauthenticated: storage can rewrite it freely. It only
/// turns a layout mismatch into a readable message before any parsing.
/// Authenticity still comes from signed manifests, which carry their own
/// version tags.
fn check_storage_format(location: &str, format: Option<&[u8]>, head_present: bool) -> Result<()> {
    let found = match format {
        Some(STORAGE_FORMAT) => return Ok(()),
        None if !head_present => return Ok(()),
        None => "5 or earlier".to_owned(),
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            let text = text.trim();
            match text.strip_prefix(STORAGE_FORMAT_PREFIX) {
                Some(version) => version.to_owned(),
                None => format!("{text:?}"),
            }
        }
    };
    bail!("storage at {location} uses format {found}; this git-remote-e2ee reads format 6")
}

/// Reads a small root file through the bounded opener.
fn read_root_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>> {
    match bounded::read_regular_bounded(path, max_bytes)
        .with_context(|| format!("read {}", path.display()))?
    {
        Bounded::Absent => Ok(None),
        Bounded::Within(bytes) => Ok(Some(bytes)),
        Bounded::Oversized => bail!("{} exceeds {max_bytes} bytes", path.display()),
        Bounded::NotRegular => bail!("{} is not a regular file", path.display()),
    }
}

impl ObjectKind {
    fn directory(self) -> &'static str {
        match self {
            Self::Pack => "packs",
            Self::Manifest => "manifests",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Manifest => "manifest",
        }
    }

    pub fn max_bytes(self) -> u64 {
        match self {
            Self::Pack => MAX_OBJECT_BYTES,
            Self::Manifest => MAX_MANIFEST_BYTES,
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
        for name in [
            ObjectKind::Pack.directory(),
            ObjectKind::Manifest.directory(),
        ] {
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

    fn check_format(&self) -> Result<()> {
        let format = read_root_file(&self.root.join("FORMAT"), MAX_STORAGE_FORMAT_BYTES)?;
        let head_present = fs::symlink_metadata(self.root.join("HEAD")).is_ok();
        check_storage_format(
            &self.root.display().to_string(),
            format.as_deref(),
            head_present,
        )
    }

    /// Writes the root notice and `FORMAT` before the genesis HEAD, so a
    /// published HEAD always has a `FORMAT` beside it.
    fn write_genesis_files(&self) -> Result<()> {
        let readme = self.root.join("README.md");
        if !readme.exists() {
            crate::persist::replace_file_durably(
                &self.root,
                "README.md",
                storage_readme("This directory").as_bytes(),
            )?;
        }
        crate::persist::replace_file_durably(&self.root, "FORMAT", STORAGE_FORMAT)?;
        Ok(())
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
        Ok(ValidatingObjectStage::wrap(
            FilesystemObjectStage {
                file,
                temporary,
                root: self.root.clone(),
                kind,
            },
            kind,
        ))
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        let path = self.object_path(kind, id)?;
        let refused = |kind, reason: &str| Some(std::io::Error::new(kind, reason.to_owned()));
        let source = match bounded::open_regular(&path) {
            Ok(Opened::Regular(file, length)) if length <= kind.max_bytes() => {
                return Ok(Box::new(file.take(kind.max_bytes())));
            }
            Ok(Opened::Regular(..)) => refused(
                std::io::ErrorKind::InvalidData,
                "object exceeds the maximum object size",
            ),
            Ok(Opened::NotRegular) => refused(
                std::io::ErrorKind::InvalidData,
                "object is not a regular file",
            ),
            Ok(Opened::Absent) => Some(std::io::ErrorKind::NotFound.into()),
            Err(error) => Some(error),
        };
        Err(ObjectUnavailable {
            storage: "directory",
            id: id.to_owned(),
            source,
        })
        .with_context(|| format!("read {}", path.display()))
    }

    fn read_head(&self) -> Result<Option<String>> {
        self.check_format()?;
        read_stored_head(&self.root.join("HEAD"))?
            .map(|head| head.parse())
            .transpose()
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
        if actual.is_none()
            && let Err(error) = self.write_genesis_files()
        {
            fs2::FileExt::unlock(&lock)?;
            return Err(error);
        }

        crate::persist::replace_file_durably(&self.root, "HEAD", format!("{next}\n").as_bytes())?;
        fs2::FileExt::unlock(&lock)?;
        Ok(())
    }

    fn observe_head(&self) -> Result<HeadObservation> {
        self.check_format()?;
        let head = read_stored_head(&self.root.join("HEAD"))?;
        Ok(HeadObservation {
            head_id: head.as_ref().and_then(StoredHead::head_id),
            token: head
                .as_ref()
                .map(|head| head.evidence().to_vec())
                .unwrap_or_default(),
            head,
        })
    }

    fn compare_and_swap_observed_head(&self, observed: &HeadObservation, next: &str) -> Result<()> {
        validate_id(next)?;
        let lock = self.lock_file()?;
        lock.lock_exclusive()?;
        let actual = match read_stored_head(&self.root.join("HEAD")) {
            Ok(actual) => actual,
            Err(error) => {
                fs2::FileExt::unlock(&lock)?;
                return Err(error);
            }
        };
        if actual != observed.head {
            let actual_id = actual.as_ref().and_then(StoredHead::head_id);
            fs2::FileExt::unlock(&lock)?;
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: actual_id,
            }
            .into());
        }
        if actual.is_none()
            && let Err(error) = self.write_genesis_files()
        {
            fs2::FileExt::unlock(&lock)?;
            return Err(error);
        }

        crate::persist::replace_file_durably(&self.root, "HEAD", format!("{next}\n").as_bytes())?;
        fs2::FileExt::unlock(&lock)?;
        Ok(())
    }
}

fn read_stored_head(path: &Path) -> Result<Option<StoredHead>> {
    let bounded =
        bounded::read_regular_bounded(path, MAX_HEAD_BYTES).context("read storage HEAD")?;
    Ok(StoredHead::from_bounded(bounded))
}

fn validate_id(id: &str) -> Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
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
    let Opened::Regular(file, _) = bounded::open_regular(path)? else {
        bail!("stored object {id} is not a regular file")
    };
    if reader_id(file)? != id {
        bail!("object id collision for {id}")
    }
    Ok(())
}

const CARRIER_DEFAULT_BRANCH: &str = "main";
const CARRIER_CHUNK_SIZE: usize = CARRIER_CHUNK_BYTES as usize;
/// Bounds one object's `ls-tree` listing: a few hundred bytes per chunk entry.
const MAX_CARRIER_LISTING_BYTES: u64 = 8 * 1024 * 1024;
const CARRIER_ATTRIBUTES: &[u8] = b"* -delta\n";
const CARRIER_CACHE_ENV: &str = "GIT_REMOTE_E2EE_CACHE_DIR";
/// Each cache serves one (remote, branch) pair, so one fixed ref suffices.
const CARRIER_CACHE_FETCH_REF: &str = "refs/heads/carrier";
/// Every path a carrier publication may contain, relative to the branch root.
const CARRIER_ROOT_ENTRIES: [&str; 6] = [
    ".gitattributes",
    "README.md",
    "FORMAT",
    "HEAD",
    "manifests",
    "packs",
];
const MAX_RECOVERY_OUTER_COMMITS: usize = 2048;
const CARRIER_COMMIT_MESSAGE: &str = "git-remote-e2ee storage update";
const CARRIER_IDENTITY: (&str, &str) = ("git-remote-e2ee", "git-remote-e2ee@invalid");

pub struct GitStorage {
    checkout: tempfile::TempDir,
    location: String,
    remote: String,
    branch: String,
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
            let Opened::Regular(file, _) = bounded::open_regular(&self.paths[self.next])? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "carrier object chunk is not a regular file",
                ));
            };
            self.current = Some(file);
            self.next += 1;
        }
    }
}

/// Reads one blob of at most `max_bytes` from a carrier commit.
fn carrier_blob(repo: &Path, object: &str, max_bytes: u64) -> Result<Bounded> {
    let mut cat = CatFile::batch(&GitRepository::owned_work_tree(repo))?;
    let size = match cat.request(object)? {
        BatchHeader::Missing => return Ok(Bounded::Absent),
        BatchHeader::Object { kind, .. } if kind != GitObjectType::Blob => {
            return Ok(Bounded::NotRegular);
        }
        BatchHeader::Object { size, .. } if size > max_bytes => return Ok(Bounded::Oversized),
        BatchHeader::Object { size, .. } => size,
    };
    let mut bytes = vec![0_u8; size as usize];
    cat.body().read_exact(&mut bytes)?;
    cat.end_body()?;
    cat.finish()?;
    Ok(Bounded::Within(bytes))
}

/// Streams a carrier object's chunk blobs. A chunk whose header shows the
/// wrong type or size fails with `InvalidData` before its body is read.
struct GitChunkReader {
    cat: CatFile,
    chunks: Vec<(String, String)>,
    next: usize,
    remaining: u64,
    trace: trace::Io,
}

impl GitChunkReader {
    fn new(repo: &Path, chunks: Vec<(String, String)>) -> Result<Self> {
        Ok(Self {
            cat: CatFile::batch(&GitRepository::owned_work_tree(repo))?,
            chunks,
            next: 0,
            remaining: 0,
            trace: trace::Io::new("carrier_object_read"),
        })
    }

    /// The index of the chunk the last read came from.
    fn chunk_index(&self) -> usize {
        self.next.saturating_sub(1)
    }

    fn start_next_chunk(&mut self) -> std::io::Result<()> {
        let expected = &self.chunks[self.next].1;
        let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
        let size = match self.cat.request(expected)? {
            BatchHeader::Object { id, kind, size }
                if id == *expected && kind == GitObjectType::Blob =>
            {
                size
            }
            _ => {
                return Err(invalid(
                    "git cat-file returned an invalid carrier chunk header",
                ));
            }
        };
        let last = self.next + 1 == self.chunks.len();
        if (!last && size != CARRIER_CHUNK_BYTES)
            || (last && (size == 0 || size > CARRIER_CHUNK_BYTES))
        {
            return Err(invalid("carrier object chunk has invalid size"));
        }
        self.next += 1;
        self.remaining = size;
        Ok(())
    }
}

impl Read for GitChunkReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let started = self.trace.is_active().then(std::time::Instant::now);
        if self.remaining == 0 {
            if self.next == self.chunks.len() {
                self.cat.finish()?;
                self.trace
                    .record(0, started.map_or(0, |started| started.elapsed().as_nanos()));
                return Ok(0);
            }
            self.start_next_chunk()?;
        }
        let amount = output.len().min(self.remaining as usize);
        let read = self.cat.body().read(&mut output[..amount])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "git cat-file truncated a carrier chunk",
            ));
        }
        self.remaining -= read as u64;
        if self.remaining == 0 {
            self.cat.end_body()?;
        }
        self.trace.record(
            read,
            started.map_or(0, |started| started.elapsed().as_nanos()),
        );
        Ok(read)
    }
}

struct CarrierObjectStage {
    staging: PathBuf,
    root: PathBuf,
    kind: ObjectKind,
    current: Option<File>,
    chunk_index: usize,
    chunk_len: usize,
    trace: trace::Io,
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
        let started = self.trace.is_active().then(std::time::Instant::now);
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
        self.trace.record(
            original,
            started.map_or(0, |started| started.elapsed().as_nanos()),
        );
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
    /// Opens `remote`, optionally suffixed with `#<branch>` to select the
    /// carrier branch (default `main`).
    pub fn open(location: &str) -> Result<Self> {
        let (remote, branch) = parse_carrier_location(location)?;
        let remote = remote.as_str();
        let branch = branch.as_str();

        let lock_timer = trace::Span::new("carrier_cache_lock");
        let mut cache = CarrierCache::lock(remote, branch)?;
        drop(lock_timer);
        let fetch_timer = trace::Span::new("carrier_cache_fetch");
        let mut base_commit = cache.refresh(remote, branch)?;
        drop(fetch_timer);
        let mut checkout = tempfile::Builder::new()
            .prefix("git-remote-e2ee-carrier-")
            .tempdir()?;
        let checkout_timer = trace::Span::new("carrier_checkout_create");
        if let Err(error) =
            create_carrier_checkout(checkout.path(), &cache.path, remote, branch, &base_commit)
        {
            if !cache.is_corrupt()? {
                return Err(error).context("create carrier checkout");
            }
            drop(checkout);
            cache.rebuild()?;
            base_commit = cache.refresh(remote, branch)?;
            checkout = tempfile::Builder::new()
                .prefix("git-remote-e2ee-carrier-")
                .tempdir()?;
            create_carrier_checkout(checkout.path(), &cache.path, remote, branch, &base_commit)
                .context("create carrier checkout after rebuilding corrupt cache")?;
        }
        drop(checkout_timer);
        drop(cache);

        Ok(Self {
            checkout,
            location: location.to_owned(),
            remote: remote.to_owned(),
            branch: branch.to_owned(),
            state: Mutex::new(GitStorageState { base_commit }),
        })
    }

    fn root(&self) -> &Path {
        self.checkout.path()
    }

    fn object_directory(&self, kind: ObjectKind, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        Ok(self.root().join(kind.directory()).join(&id[..2]).join(id))
    }

    /// Reads a root file from the checkout, falling back to the opened
    /// commit because the checkout only populates the index.
    fn local_root_file(&self, name: &str, max_bytes: u64) -> Result<Bounded> {
        let path = self.root().join(name);
        match bounded::read_regular_bounded(&path, max_bytes)
            .with_context(|| format!("read carrier {name}"))?
        {
            Bounded::Absent => {
                let Some(commit) = git_rev_parse(self.root(), "HEAD")? else {
                    return Ok(Bounded::Absent);
                };
                carrier_blob(self.root(), &format!("{commit}:{name}"), max_bytes)
            }
            found => Ok(found),
        }
    }

    fn check_format(&self) -> Result<()> {
        let format = match self.local_root_file("FORMAT", MAX_STORAGE_FORMAT_BYTES)? {
            Bounded::Absent => None,
            Bounded::Within(bytes) => Some(bytes),
            Bounded::Oversized | Bounded::NotRegular => {
                bail!("carrier FORMAT is not a small regular file")
            }
        };
        let head_present = !matches!(
            self.local_root_file("HEAD", MAX_HEAD_BYTES)?,
            Bounded::Absent
        );
        check_storage_format(&self.location, format.as_deref(), head_present)
    }

    /// Writes HEAD into the checkout, plus the root notice and `FORMAT`
    /// when this publication creates the branch.
    fn write_checkout_head(&self, next: &str, genesis: bool) -> Result<()> {
        if genesis {
            fs::write(self.root().join("README.md"), storage_readme("This branch"))?;
            fs::write(self.root().join("FORMAT"), STORAGE_FORMAT)?;
        }
        fs::write(self.root().join("HEAD"), format!("{next}\n"))?;
        Ok(())
    }

    /// A carrier branch that exists without a HEAD holds someone else's
    /// content (for example a hosting provider's initial README).
    fn refuse_foreign_branch(&self, base_commit: &Option<String>) -> Result<()> {
        if base_commit.is_some() {
            return Err(StorageOccupied(format!(
                "branch {branch} of {remote} already exists; use an empty repository or choose another branch with e2ee::{remote}#<branch>",
                branch = self.branch,
                remote = self.remote,
            ))
            .into());
        }
        Ok(())
    }

    fn local_head(&self) -> Result<Option<String>> {
        self.local_stored_head()?
            .map(|head| head.parse())
            .transpose()
    }

    fn local_stored_head(&self) -> Result<Option<StoredHead>> {
        self.check_format()?;
        Ok(StoredHead::from_bounded(
            self.local_root_file("HEAD", MAX_HEAD_BYTES)?,
        ))
    }

    /// The manifest ID a conflicting remote tip names, for diagnostics only:
    /// a tip whose HEAD is missing or malformed still wins the conflict.
    fn conflicting_head(&self, commit: Option<&str>) -> Option<String> {
        self.stored_head_at_commit(commit?).ok()??.head_id()
    }

    fn stored_head_at_commit(&self, commit: &str) -> Result<Option<StoredHead>> {
        Ok(StoredHead::from_bounded(carrier_blob(
            self.root(),
            &format!("{commit}:HEAD"),
            MAX_HEAD_BYTES,
        )?))
    }

    fn commit_history(&self, limit: usize) -> Result<Vec<String>> {
        let maximum = limit.saturating_add(1).to_string();
        let output = GitRepository::owned_work_tree(self.root())
            .git()
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

    fn chunk_entries_at(&self, commit: &str, kind: ObjectKind, id: &str) -> Result<CarrierListing> {
        carrier_chunk_entries(self.root(), commit, kind, id)
    }

    /// Commits in `window` whose tree changed the stored copy of `id`, newest
    /// first. Carrier history is linear, so each one starts a distinct copy.
    fn copy_commits(&self, window: &[String], kind: ObjectKind, id: &str) -> Result<Vec<String>> {
        validate_id(id)?;
        let Some(newest) = window.first() else {
            return Ok(Vec::new());
        };
        let directory = format!("{}/{}/{id}", kind.directory(), &id[..2]);
        let output = GitRepository::owned_work_tree(self.root())
            .git()
            .args([
                "rev-list",
                &format!("--max-count={}", window.len()),
                newest,
                "--",
                &directory,
            ])
            .output()?;
        ensure_git_success(&output, "git rev-list carrier object copies")?;
        let window: HashSet<&str> = window.iter().map(String::as_str).collect();
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .filter(|commit| window.contains(commit))
            .map(ToOwned::to_owned)
            .collect())
    }

    /// Streams the copy of `id` stored at `commit` into `sink` as
    /// `(chunk index, bytes)` pieces. Returns false when the commit holds no
    /// copy or the copy is malformed or does not hash to `id`; `sink` sees
    /// every byte read, including those of a copy later rejected. `sink`
    /// errors and process failures propagate.
    fn read_copy_at(
        &self,
        commit: &str,
        kind: ObjectKind,
        id: &str,
        mut sink: impl FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<bool> {
        let CarrierListing::Chunks(chunks) = self.chunk_entries_at(commit, kind, id)? else {
            return Ok(false);
        };
        let mut reader = GitChunkReader::new(self.root(), chunks)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            sink(reader.chunk_index(), &buffer[..read])?;
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()) == id)
    }

    /// Publishes `next` on top of `base_commit`. On failure the checkout is
    /// restored to `base_commit`, so later reads through this storage never
    /// see an unpublished HEAD and later publications never carry it.
    fn publish_checkout_head(
        &self,
        next: &str,
        expected: Option<String>,
        base_commit: &Option<String>,
        cache: &mut CarrierCache,
    ) -> Result<String> {
        let result = self.commit_and_push_head(next, expected, base_commit, cache);
        if let Err(error) = result {
            return Err(match self.restore_checkout(base_commit) {
                Ok(()) => error,
                Err(restore) => error.context(format!(
                    "restoring the carrier checkout after a failed publication also failed: {restore:#}"
                )),
            });
        }
        result
    }

    fn commit_and_push_head(
        &self,
        next: &str,
        expected: Option<String>,
        base_commit: &Option<String>,
        cache: &mut CarrierCache,
    ) -> Result<String> {
        self.write_checkout_head(next, base_commit.is_none())?;
        let add_timer = trace::Span::new("carrier_git_add");
        stage_carrier_checkout(self.root(), &cache.path.join("objects"))?;
        drop(add_timer);
        let commit_timer = trace::Span::new("carrier_git_commit");
        let objects = cache.path.join("objects");
        let tree = git_text_with_object_directory(self.root(), &objects, &["write-tree"])?;
        let mut commit_tree = vec!["commit-tree", "--no-gpg-sign", "-m", CARRIER_COMMIT_MESSAGE];
        if let Some(parent) = base_commit {
            commit_tree.extend(["-p", parent]);
        }
        commit_tree.push(&tree);
        let new_commit = git_text_with_object_directory(self.root(), &objects, &commit_tree)?;
        git_command(
            self.root(),
            &[
                "update-ref",
                &format!("refs/heads/{}", self.branch),
                &new_commit,
            ],
        )?;
        drop(commit_timer);
        let push_timer = trace::Span::new("carrier_git_push");
        let push = GitRepository::owned_work_tree(self.root())
            .transport()
            .args(["push", "--quiet", "--no-verify", "origin"])
            .arg(format!("HEAD:refs/heads/{}", self.branch))
            .output()?;
        drop(push_timer);
        if !push.status.success() {
            let push_error = anyhow::anyhow!(
                "git push carrier branch failed: {}",
                String::from_utf8_lossy(&push.stderr).trim()
            );
            // Only an observed move of the remote tip is a lost race; a push
            // refused for any other reason leaves the tip at `base_commit`.
            let Ok(latest) = cache.refresh(&self.remote, &self.branch) else {
                return Err(push_error);
            };
            if latest.as_deref() != Some(new_commit.as_str()) {
                if latest == *base_commit {
                    return Err(push_error);
                }
                return Err(CasConflict {
                    expected,
                    actual: self.conflicting_head(latest.as_deref()),
                }
                .into());
            }
        }
        cache.update_published_tip(&new_commit)?;
        Ok(new_commit)
    }

    /// Points the local branch and index back at `base_commit` and removes
    /// every working-tree file the failed publication added or changed.
    fn restore_checkout(&self, base_commit: &Option<String>) -> Result<()> {
        let root = self.root();
        let local_ref = format!("refs/heads/{}", self.branch);
        match base_commit {
            Some(commit) => {
                git_command(root, &["update-ref", &local_ref, commit])?;
                git_command(root, &["read-tree", commit])?;
            }
            None => {
                if git_rev_parse(root, &local_ref)?.is_some() {
                    git_command(root, &["update-ref", "-d", &local_ref])?;
                }
                git_command(root, &["read-tree", "--empty"])?;
            }
        }
        // The checkout is sparse: a missing HEAD file falls back to the
        // committed one.
        match fs::remove_file(root.join("HEAD")) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let untracked = GitRepository::owned_work_tree(root)
            .git()
            .args([
                "ls-files",
                "--others",
                "-z",
                "--",
                "README.md",
                "FORMAT",
                "manifests",
                "packs",
            ])
            .output()?;
        ensure_git_success(&untracked, "git ls-files carrier checkout")?;
        for path in untracked.stdout.split(|byte| *byte == 0) {
            if path.is_empty() {
                continue;
            }
            let path = std::str::from_utf8(path).context("carrier checkout path is not UTF-8")?;
            fs::remove_file(root.join(path))?;
        }
        Ok(())
    }
}

impl Storage for GitStorage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        let staging = self.root().join(format!(".stage-{}", hex::encode(random)));
        fs::create_dir(&staging)?;
        Ok(ValidatingObjectStage::wrap(
            CarrierObjectStage {
                staging,
                root: self.root().to_path_buf(),
                kind,
                current: None,
                chunk_index: 0,
                chunk_len: 0,
                trace: trace::Io::new("carrier_stage_write"),
            },
            kind,
        ))
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        let directory = self.object_directory(kind, id)?;
        if directory.exists() {
            let paths = validated_chunk_paths(&directory)?;
            return Ok(Box::new(ChunkReader {
                paths,
                next: 0,
                current: None,
                trace: trace::Io::new("carrier_object_read"),
            }));
        }
        let unavailable = || ObjectUnavailable {
            storage: "carrier",
            id: id.to_owned(),
            source: None,
        };
        let Some(commit) = git_rev_parse(self.root(), "HEAD")? else {
            bail!(unavailable())
        };
        let chunks = match self.chunk_entries_at(&commit, kind, id)? {
            CarrierListing::Chunks(chunks) => chunks,
            CarrierListing::Absent => bail!(unavailable()),
            CarrierListing::Malformed(reason) => bail!("carrier object {id}: {reason}"),
        };
        Ok(Box::new(GitChunkReader::new(self.root(), chunks)?))
    }

    fn read_head(&self) -> Result<Option<String>> {
        // `open` refreshed the remote before constructing this checkout; CAS
        // refreshes again before trusting this snapshot for a write.
        self.local_head()
    }

    fn refresh(&self) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let mut cache = CarrierCache::lock(&self.remote, &self.branch)?;
        let remote_tip = cache.refresh(&self.remote, &self.branch)?;
        if remote_tip == state.base_commit {
            return Ok(false);
        }
        self.restore_checkout(&remote_tip)?;
        state.base_commit = remote_tip;
        Ok(true)
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        validate_id(next)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let mut cache = CarrierCache::lock(&self.remote, &self.branch)?;
        let refresh_timer = trace::Span::new("carrier_cas_refresh");
        let remote_tip = cache.refresh(&self.remote, &self.branch)?;
        drop(refresh_timer);
        if remote_tip != state.base_commit {
            return Err(CasConflict {
                expected: expected.map(ToOwned::to_owned),
                actual: self.conflicting_head(remote_tip.as_deref()),
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
        if actual.is_none() {
            self.refuse_foreign_branch(&state.base_commit)?;
        }
        let new_commit = self.publish_checkout_head(
            next,
            expected.map(ToOwned::to_owned),
            &state.base_commit,
            &mut cache,
        )?;
        state.base_commit = Some(new_commit);
        Ok(())
    }

    fn observe_head(&self) -> Result<HeadObservation> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("carrier state lock poisoned"))?;
        let head = self.local_stored_head()?;
        Ok(HeadObservation {
            head_id: head.as_ref().and_then(StoredHead::head_id),
            token: state
                .base_commit
                .as_deref()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
            head,
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
        let mut cache = CarrierCache::lock(&self.remote, &self.branch)?;
        let remote_tip = cache.refresh(&self.remote, &self.branch)?;
        if remote_tip != expected_tip {
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: self.conflicting_head(remote_tip.as_deref()),
            }
            .into());
        }
        let actual = self.local_stored_head()?;
        if actual != observed.head {
            return Err(CasConflict {
                expected: observed.head_id.clone(),
                actual: actual.as_ref().and_then(StoredHead::head_id),
            }
            .into());
        }
        if actual.is_none() {
            self.refuse_foreign_branch(&expected_tip)?;
        }
        let new_commit =
            self.publish_checkout_head(next, observed.head_id.clone(), &expected_tip, &mut cache)?;
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
            bail!(BudgetExhausted(
                "carrier recovery outer-commit budget exhausted".to_owned()
            ))
        }
        let mut history = RecoveryHistory::default();
        // Every byte read counts, including corrupt copies that are skipped.
        let mut total_bytes = 0_u64;
        for commit_id in &commits {
            let head_id = self
                .stored_head_at_commit(commit_id)?
                .and_then(|head| head.head_id());
            if let Some(id) = &head_id
                && !history.manifests.contains_key(id)
            {
                for copy in self.copy_commits(&commits, ObjectKind::Manifest, id)? {
                    let mut bytes = Vec::new();
                    let valid =
                        self.read_copy_at(&copy, ObjectKind::Manifest, id, |_, chunk| {
                            total_bytes = total_bytes
                                .checked_add(chunk.len() as u64)
                                .context("carrier recovery manifest byte count overflow")?;
                            if total_bytes > max_manifest_bytes {
                                bail!(BudgetExhausted(
                                    "carrier recovery manifest byte budget exhausted".to_owned()
                                ))
                            }
                            bytes.extend_from_slice(chunk);
                            Ok(())
                        })?;
                    if valid {
                        history.manifests.insert(id.clone(), bytes);
                        break;
                    }
                }
            }
            history.commits.push(RecoveryCommit {
                commit_id: commit_id.clone(),
                head_id,
            });
        }
        Ok(Some(history))
    }

    fn restore_historical_object(
        &self,
        kind: ObjectKind,
        id: &str,
        max_bytes: u64,
    ) -> Result<bool> {
        let commits = self.commit_history(MAX_RECOVERY_OUTER_COMMITS)?;
        if commits.len() > MAX_RECOVERY_OUTER_COMMITS {
            bail!(BudgetExhausted(
                "carrier recovery outer-commit budget exhausted".to_owned()
            ))
        }
        // Every byte read counts, including corrupt copies that are skipped.
        let mut total_bytes = 0_u64;
        for copy in self.copy_commits(&commits, kind, id)? {
            let staging = tempfile::Builder::new()
                .prefix("git-remote-e2ee-restore-")
                .tempdir_in(self.root())?;
            let object_dir = staging.path().join("object");
            fs::create_dir(&object_dir)?;
            let mut current: Option<(usize, File)> = None;
            let valid = self.read_copy_at(&copy, kind, id, |index, piece| {
                total_bytes = total_bytes
                    .checked_add(piece.len() as u64)
                    .context("carrier restore byte count overflow")?;
                if total_bytes > max_bytes {
                    bail!(BudgetExhausted(
                        "carrier recovery restore byte budget exhausted".to_owned()
                    ))
                }
                if current.as_ref().map(|(open, _)| *open) != Some(index) {
                    if let Some((_, file)) = current.take() {
                        file.sync_all()?;
                    }
                    let file = File::create(object_dir.join(format!("{index:08}")))?;
                    current = Some((index, file));
                }
                let (_, file) = current.as_mut().expect("chunk file opened above");
                file.write_all(piece)?;
                Ok(())
            })?;
            if let Some((_, file)) = current.take() {
                file.sync_all()?;
            }
            if !valid {
                continue;
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
            return Ok(true);
        }
        Ok(false)
    }

    fn prepare_recovery(&self, manifest_ids: &[String], pack_ids: &[String]) -> Result<()> {
        let manifests: HashSet<&str> = manifest_ids.iter().map(String::as_str).collect();
        let packs: HashSet<&str> = pack_ids.iter().map(String::as_str).collect();
        retain_carrier_objects(
            &self.root().join(ObjectKind::Manifest.directory()),
            &manifests,
        )?;
        retain_carrier_objects(&self.root().join(ObjectKind::Pack.directory()), &packs)?;
        remove_unretained_index_objects(self.root(), ObjectKind::Manifest, &manifests)?;
        remove_unretained_index_objects(self.root(), ObjectKind::Pack, &packs)?;
        Ok(())
    }
}

fn remove_unretained_index_objects(
    repo: &Path,
    kind: ObjectKind,
    keep: &HashSet<&str>,
) -> Result<()> {
    let tree = kind.directory();
    let output = GitRepository::owned_work_tree(repo)
        .git()
        .args(["ls-files", "-z", "--", tree])
        .output()?;
    ensure_git_success(&output, "git ls-files carrier recovery objects")?;
    let mut remove = Vec::new();
    for path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(path)?;
        let mut fields = path.split('/');
        if fields.next() != Some(kind.directory()) {
            bail!("unexpected carrier index path during recovery")
        }
        let _prefix = fields.next().context("carrier index path has no prefix")?;
        let id = fields
            .next()
            .context("carrier index path has no object id")?;
        let _chunk = fields.next().context("carrier index path has no chunk")?;
        if fields.next().is_some() {
            bail!("unexpected carrier index path depth during recovery")
        }
        if !keep.contains(id) {
            remove.extend_from_slice(path.as_bytes());
            remove.push(0);
        }
    }
    if !remove.is_empty() {
        git_command_with_input(
            repo,
            &["update-index", "--force-remove", "-z", "--stdin"],
            &remove,
        )?;
    }
    Ok(())
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

/// What one carrier commit holds for an object.
enum CarrierListing {
    Absent,
    /// Storage-controlled entries that do not form a valid chunk sequence.
    Malformed(&'static str),
    Chunks(Vec<(String, String)>),
}

/// Lists the chunks of `id` at `commit`. Malformed storage content is a
/// `CarrierListing`; only Git or I/O failure is an error.
fn carrier_chunk_entries(
    repo: &Path,
    commit: &str,
    kind: ObjectKind,
    id: &str,
) -> Result<CarrierListing> {
    validate_id(id)?;
    let directory = format!("{}/{}/{id}", kind.directory(), &id[..2]);
    let mut child = GitRepository::owned_work_tree(repo)
        .git()
        .args(["ls-tree", "-r", "-z", commit, "--", &directory])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut listing = Vec::new();
    child
        .stdout
        .take()
        .context("open git ls-tree stdout")?
        .take(MAX_CARRIER_LISTING_BYTES + 1)
        .read_to_end(&mut listing)?;
    if listing.len() as u64 > MAX_CARRIER_LISTING_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(CarrierListing::Malformed(
            "carrier object listing exceeds its size budget",
        ));
    }
    let output = child.wait_with_output()?;
    ensure_git_success(&output, "git ls-tree carrier object")?;
    if listing.is_empty() {
        return Ok(CarrierListing::Absent);
    }
    Ok(match parse_chunk_listing(&listing, &directory) {
        Ok(chunks) => CarrierListing::Chunks(chunks),
        Err(reason) => CarrierListing::Malformed(reason),
    })
}

fn parse_chunk_listing(
    listing: &[u8],
    directory: &str,
) -> std::result::Result<Vec<(String, String)>, &'static str> {
    let mut chunks = Vec::new();
    for entry in listing
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("carrier tree entry has no path")?;
        let (metadata, path) = (&entry[..tab], &entry[tab + 1..]);
        let metadata =
            std::str::from_utf8(metadata).map_err(|_| "carrier tree entry is not UTF-8")?;
        let path = std::str::from_utf8(path)
            .map_err(|_| "carrier object path is not UTF-8")?
            .to_owned();
        let mut fields = metadata.split_ascii_whitespace();
        if fields.next() != Some("100644") || fields.next() != Some("blob") {
            return Err("carrier object contains a non-regular blob");
        }
        let blob_id = fields.next().ok_or("carrier blob has no id")?;
        if fields.next().is_some() || !path.starts_with(&format!("{directory}/")) {
            return Err("unexpected carrier object path");
        }
        chunks.push((path, blob_id.to_owned()));
    }
    chunks.sort_by(|left, right| left.0.cmp(&right.0));
    if chunks.is_empty() || chunks.len() as u64 > MAX_CHUNKS_PER_OBJECT {
        return Err("carrier object has an invalid chunk count");
    }
    for (index, (path, _)) in chunks.iter().enumerate() {
        if *path != format!("{directory}/{index:08}") {
            return Err("carrier object chunks are not a dense canonical sequence");
        }
    }
    Ok(chunks)
}

struct CarrierCache {
    remote_dir: PathBuf,
    path: PathBuf,
    _lock: File,
}

impl CarrierCache {
    fn lock(remote: &str, branch: &str) -> Result<Self> {
        let normalized = normalize_carrier_remote(remote)?;
        let key = format!("{normalized}#{branch}");
        let hash = hex::encode(Sha256::digest(key.as_bytes()));
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

    fn refresh(&mut self, remote: &str, branch: &str) -> Result<Option<String>> {
        let initialize_timer = trace::Span::new("carrier_cache_initialize");
        self.ensure_initialized()?;
        drop(initialize_timer);
        let fetch_timer = trace::Span::new("carrier_cache_fetch_remote");
        match fetch_carrier_branch(&self.path, remote, branch) {
            Ok(tip) => {
                drop(fetch_timer);
                Ok(tip)
            }
            Err(FetchError::Local(fetch_error)) if self.is_corrupt()? => {
                self.rebuild()?;
                let result = fetch_carrier_branch(&self.path, remote, branch)
                    .map_err(FetchError::into_inner)
                    .with_context(|| {
                    format!(
                        "fetch carrier branch after rebuilding corrupt cache (initial fetch failed: {fetch_error:#})"
                    )
                });
                drop(fetch_timer);
                result
            }
            Err(FetchError::Local(error) | FetchError::Remote(error)) => {
                drop(fetch_timer);
                Err(error)
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
        let output = gitcmd::without_repository()
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

    /// Publishes a fresh generation and removes the ones it replaces. A
    /// process that opened its checkout before the rebuild and still borrows
    /// a removed generation fails its later object reads instead of reading
    /// from a corrupt store.
    fn rebuild(&mut self) -> Result<()> {
        self.initialize_generation()?;
        let current = self.path.file_name().map(ToOwned::to_owned);
        for entry in fs::read_dir(&self.remote_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let replaced = name.to_str().is_some_and(valid_cache_generation)
                && Some(&name) != current.as_ref();
            if replaced {
                fs::remove_dir_all(entry.path()).with_context(|| {
                    format!("remove replaced carrier cache {}", entry.path().display())
                })?;
            }
        }
        Ok(())
    }

    fn publish_current(&self) -> Result<()> {
        let generation = self
            .path
            .file_name()
            .context("carrier cache generation has no name")?;
        let generation = generation
            .to_str()
            .context("carrier cache generation name is not UTF-8")?;
        crate::persist::replace_file_durably(
            &self.remote_dir,
            "current",
            format!("{generation}\n").as_bytes(),
        )?;
        Ok(())
    }

    fn update_published_tip(&self, commit: &str) -> Result<()> {
        cache_git_command(&self.path, &["update-ref", CARRIER_CACHE_FETCH_REF, commit])
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

/// Splits `remote#branch` on the last `#`; without a `#` the branch is
/// `main`.
fn parse_carrier_location(location: &str) -> Result<(String, String)> {
    let (remote, branch) = match location.rsplit_once('#') {
        Some((remote, branch)) => (remote, branch),
        None => (location, CARRIER_DEFAULT_BRANCH),
    };
    if remote.is_empty() {
        bail!("empty carrier Git remote")
    }
    if branch.is_empty() {
        bail!("empty carrier branch in {location:?}")
    }
    if !refname::is_valid(&format!("refs/heads/{branch}")) || branch.starts_with('-') {
        bail!("invalid carrier branch name {branch:?} in {location:?}")
    }
    Ok((remote.to_owned(), branch.to_owned()))
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
    configure_git_pack_settings(|key, value| cache_git_command(cache, &["config", key, value]))?;
    Ok(())
}

fn configure_git_pack_settings(mut configure: impl FnMut(&str, &str) -> Result<()>) -> Result<()> {
    for (key, value) in [
        ("core.compression", "0"),
        ("core.looseCompression", "0"),
        ("pack.compression", "0"),
        ("pack.window", "0"),
        ("pack.depth", "0"),
        ("core.bigFileThreshold", "1m"),
    ] {
        configure(key, value)?;
    }
    Ok(())
}

/// Why a carrier fetch failed. Only a failure while the remote is reachable
/// can come from the local cache, so only that one justifies a corruption
/// check.
enum FetchError {
    Remote(anyhow::Error),
    Local(anyhow::Error),
}

impl FetchError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Remote(error) | Self::Local(error) => error,
        }
    }
}

fn fetch_carrier_branch(
    cache: &Path,
    remote: &str,
    branch: &str,
) -> std::result::Result<Option<String>, FetchError> {
    let remote_ref = format!("refs/heads/{branch}");
    let refspec = format!("+{remote_ref}:{CARRIER_CACHE_FETCH_REF}");
    let fetch = cache_transport_output(cache, &["fetch", "--quiet", "--no-tags", remote, &refspec])
        .map_err(FetchError::Local)?;
    if fetch.status.success() {
        return git_rev_parse(cache, CARRIER_CACHE_FETCH_REF).map_err(FetchError::Local);
    }

    let ls_remote = cache_transport_output(cache, &["ls-remote", "--heads", remote, &remote_ref])
        .and_then(|output| {
            ensure_git_success(&output, "git ls-remote carrier branch")?;
            Ok(output)
        })
        .map_err(|error| {
            FetchError::Remote(error.context(format!(
                "git fetch carrier branch failed: {}",
                String::from_utf8_lossy(&fetch.stderr).trim()
            )))
        })?;
    if String::from_utf8_lossy(&ls_remote.stdout).trim().is_empty() {
        cache_git_output(cache, &["update-ref", "-d", CARRIER_CACHE_FETCH_REF])
            .and_then(|output| {
                ensure_git_success(&output, "git update-ref delete missing carrier branch")
            })
            .map_err(FetchError::Local)?;
        return Ok(None);
    }
    Err(FetchError::Local(anyhow::anyhow!(
        "git fetch carrier branch failed: {}",
        String::from_utf8_lossy(&fetch.stderr).trim()
    )))
}

fn create_carrier_checkout(
    checkout: &Path,
    cache: &Path,
    remote: &str,
    branch: &str,
    base_commit: &Option<String>,
) -> Result<()> {
    let _timer = trace::Span::new("carrier_checkout_git_setup");
    let output = GitRepository::owned_work_tree(checkout)
        .git()
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
    configure_git_pack_settings(|key, value| git_command(checkout, &["config", key, value]))?;
    git_command(checkout, &["remote", "add", "origin", remote])?;

    let remote_ref = format!("refs/remotes/origin/{branch}");
    match base_commit {
        Some(commit) => {
            git_command(checkout, &["update-ref", &remote_ref, commit])?;
            let local_ref = format!("refs/heads/{branch}");
            git_command(checkout, &["update-ref", &local_ref, commit])?;
            git_command(checkout, &["symbolic-ref", "HEAD", &local_ref])?;
            git_command(checkout, &["read-tree", commit])?;
        }
        None => {
            git_command(checkout, &["checkout", "--quiet", "--orphan", branch])?;
        }
    }
    fs::write(checkout.join(".gitattributes"), CARRIER_ATTRIBUTES)?;
    Ok(())
}

/// `None` when `reference` names nothing; any other Git failure is an error.
fn git_rev_parse(repo: &Path, reference: &str) -> Result<Option<String>> {
    let output = GitRepository::owned_work_tree(repo)
        .git()
        .args(["rev-parse", "--verify", "--quiet", reference])
        .output()?;
    match output.status.code() {
        Some(0) => Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned())),
        Some(1) => Ok(None),
        _ => {
            ensure_git_success(&output, &format!("git rev-parse {reference}"))?;
            unreachable!("a failed rev-parse is an error")
        }
    }
}

fn cache_git_command(cache: &Path, args: &[&str]) -> Result<()> {
    let output = cache_git_output(cache, args)?;
    ensure_git_success(&output, &format!("git {}", args.join(" ")))
}

fn cache_git_output(cache: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(GitRepository::owned_git_dir(cache)
        .git()
        .args(args)
        .output()?)
}

fn cache_transport_output(cache: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(GitRepository::owned_git_dir(cache)
        .transport()
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
    let output = GitRepository::owned_work_tree(repo)
        .git()
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

fn git_command_with_input(repo: &Path, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = GitRepository::owned_work_tree(repo)
        .git()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("open git stdin")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn stage_carrier_checkout(repo: &Path, object_directory: &Path) -> Result<()> {
    fn collect(root: &Path, path: &Path, output: &mut Vec<u8>) -> Result<()> {
        let entry = fs::symlink_metadata(path)?;
        if entry.file_type().is_dir() {
            for child in fs::read_dir(path)? {
                collect(root, &child?.path(), output)?;
            }
        } else if entry.file_type().is_file() {
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("carrier checkout path is not UTF-8")?;
            if relative.contains('\n') || relative.contains('\0') {
                bail!("carrier checkout path contains a forbidden character")
            }
            output.extend_from_slice(relative.as_bytes());
            output.push(0);
        } else {
            bail!("carrier checkout contains a non-regular staged path")
        }
        Ok(())
    }

    let mut paths = Vec::new();
    for name in CARRIER_ROOT_ENTRIES {
        let path = repo.join(name);
        if path.exists() {
            collect(repo, &path, &mut paths)?;
        }
    }
    if paths.is_empty() {
        bail!("carrier publication has no staged files")
    }
    git_command_with_object_directory_input(
        repo,
        object_directory,
        &["add", "-A", "--pathspec-from-file=-", "--pathspec-file-nul"],
        &paths,
    )
}

/// Runs a plumbing command that writes objects into the carrier cache and
/// returns its trimmed output. Carrier commits are written this way, with a
/// fixed identity, so user hooks, signing, and identity never apply.
fn git_text_with_object_directory(
    repo: &Path,
    object_directory: &Path,
    args: &[&str],
) -> Result<String> {
    let (name, email) = CARRIER_IDENTITY;
    let output = GitRepository::owned_work_tree(repo)
        .git()
        .env("GIT_OBJECT_DIRECTORY", object_directory)
        .env("GIT_AUTHOR_NAME", name)
        .env("GIT_AUTHOR_EMAIL", email)
        .env("GIT_COMMITTER_NAME", name)
        .env("GIT_COMMITTER_EMAIL", email)
        .args(args)
        .output()?;
    ensure_git_success(&output, &format!("git {}", args.join(" ")))?;
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn git_command_with_object_directory_input(
    repo: &Path,
    object_directory: &Path,
    args: &[&str],
    input: &[u8],
) -> Result<()> {
    let mut child = GitRepository::owned_work_tree(repo)
        .git()
        .env("GIT_OBJECT_DIRECTORY", object_directory)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("open git pathspec stdin")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
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
        let mut stage = ValidatingObjectStage::wrap(
            PartialWriteSink {
                published: Arc::clone(&published),
            },
            ObjectKind::Pack,
        );
        stage.write_all(data).unwrap();
        stage.finish(&object_id(data)).unwrap();
        assert!(published.load(Ordering::Relaxed));

        let published = Arc::new(AtomicBool::new(false));
        let mut stage = ValidatingObjectStage::wrap(
            PartialWriteSink {
                published: Arc::clone(&published),
            },
            ObjectKind::Pack,
        );
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
        let data = vec![1_u8; MAX_MANIFEST_BYTES as usize + 1];
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

    fn initialized_storage() -> (tempfile::TempDir, FilesystemStorage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(directory.path());
        storage
            .compare_and_swap_head(None, &object_id(b"first"))
            .unwrap();
        (directory, storage)
    }

    fn finishes_within<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .ok()
    }

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let _ = fs::remove_file(path);
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn assert_invalid_head(storage: &FilesystemStorage, expected: StoredHead) {
        let error = storage.read_head().unwrap_err();
        assert!(
            format!("{error:#}").contains("storage HEAD is not a valid head"),
            "{error:#}"
        );
        let observed = storage.observe_head().unwrap();
        assert_eq!(observed.head_id, None);
        assert_eq!(observed.head, Some(expected));
    }

    /// Replaces HEAD with an entry no reader may accept, then checks that
    /// reads report an invalid head, a stale observation loses the CAS, and a
    /// fresh observation of the invalid head can replace it.
    fn assert_head_entry_is_an_invalid_observation(
        replace: impl FnOnce(&Path),
        expected: StoredHead,
    ) {
        let (directory, storage) = initialized_storage();
        let stale = storage.observe_head().unwrap();
        replace(&directory.path().join("HEAD"));
        let storage = Arc::new(storage);

        let reader = Arc::clone(&storage);
        let shown = expected.clone();
        let observed = finishes_within(move || {
            assert_invalid_head(&reader, shown);
            reader.observe_head().unwrap()
        })
        .expect("reading an invalid HEAD must not block");

        let writer = Arc::clone(&storage);
        let stale_error = finishes_within(move || {
            writer
                .compare_and_swap_observed_head(&stale, &object_id(b"second"))
                .unwrap_err()
        })
        .expect("CAS over an invalid HEAD must not block");
        assert!(stale_error.downcast_ref::<CasConflict>().is_some());

        let next = object_id(b"recovered");
        storage
            .compare_and_swap_observed_head(&observed, &next)
            .unwrap();
        assert_eq!(storage.read_head().unwrap(), Some(next));
        drop(directory);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_head_is_an_invalid_observation_not_a_hang() {
        assert_head_entry_is_an_invalid_observation(make_fifo, StoredHead::NotRegular);
    }

    #[cfg(unix)]
    #[test]
    fn a_head_symlink_to_a_fifo_is_an_invalid_observation_not_a_hang() {
        assert_head_entry_is_an_invalid_observation(
            |head| {
                let fifo = head.with_file_name("elsewhere");
                make_fifo(&fifo);
                fs::remove_file(head).unwrap();
                std::os::unix::fs::symlink(&fifo, head).unwrap();
            },
            StoredHead::NotRegular,
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_head_symlink_to_a_regular_file_is_not_followed() {
        assert_head_entry_is_an_invalid_observation(
            |head| {
                let target = head.with_file_name("elsewhere");
                fs::write(&target, format!("{}\n", object_id(b"first"))).unwrap();
                fs::remove_file(head).unwrap();
                std::os::unix::fs::symlink(&target, head).unwrap();
            },
            StoredHead::NotRegular,
        );
    }

    #[test]
    fn an_oversized_head_is_an_invalid_observation() {
        assert_head_entry_is_an_invalid_observation(
            |head| fs::write(head, vec![b'a'; MAX_HEAD_BYTES as usize + 1]).unwrap(),
            StoredHead::Oversized,
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_format_fails_instead_of_hanging() {
        let (directory, storage) = initialized_storage();
        make_fifo(&directory.path().join("FORMAT"));
        let result = finishes_within(move || format!("{:#}", storage.read_head().unwrap_err()));
        assert!(
            result
                .expect("reading a FIFO FORMAT must not block")
                .contains("not a regular file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_pack_fails_instead_of_hanging() {
        let (directory, storage) = initialized_storage();
        let data = b"pack bytes";
        let id = object_id(data);
        let path = storage.object_path(ObjectKind::Pack, &id).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        make_fifo(&path);
        let storage = Arc::new(storage);

        let reader = Arc::clone(&storage);
        let opened = finishes_within(move || {
            reader
                .open_object(ObjectKind::Pack, &id)
                .err()
                .map(|error| error.downcast_ref::<ObjectUnavailable>().is_some())
        });
        assert_eq!(opened, Some(Some(true)), "opening a FIFO pack must fail");

        let writer = Arc::clone(&storage);
        let written = finishes_within(move || {
            writer
                .put_object_if_absent(ObjectKind::Pack, &object_id(data), data)
                .is_err()
        });
        assert_eq!(written, Some(true), "verifying a FIFO pack must fail");
        drop(directory);
    }

    #[test]
    fn writers_refuse_a_manifest_readers_would_reject_before_publication() {
        let (directory, storage) = initialized_storage();
        let head = storage.read_head().unwrap();
        let data = vec![7_u8; MAX_MANIFEST_BYTES as usize + 1];
        let id = object_id(&data);
        let error = storage
            .put_object_if_absent(ObjectKind::Manifest, &id, &data)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("manifest object exceeds"),
            "{error:#}"
        );
        assert!(
            !storage
                .object_path(ObjectKind::Manifest, &id)
                .unwrap()
                .exists()
        );
        assert_eq!(storage.read_head().unwrap(), head);
        let manifests = directory.path().join("manifests");
        assert_eq!(fs::read_dir(manifests).unwrap().count(), 0);
        drop(directory);
    }

    #[test]
    fn object_ids_must_be_lowercase_hex() {
        validate_id(&"ab".repeat(32)).unwrap();
        assert!(validate_id(&"AB".repeat(32)).is_err());
    }

    fn checkout_git(root: &Path, args: &[&str]) -> String {
        let output = GitRepository::owned_work_tree(root)
            .git()
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn a_failed_carrier_listing_is_an_error_not_a_missing_copy() {
        let checkout = tempfile::tempdir().unwrap();
        checkout_git(checkout.path(), &["init", "--quiet"]);
        fs::write(checkout.path().join("FORMAT"), STORAGE_FORMAT).unwrap();
        checkout_git(checkout.path(), &["add", "FORMAT"]);
        let tree = checkout_git(checkout.path(), &["write-tree"]);
        let commit = checkout_git(
            checkout.path(),
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@invalid",
                "commit-tree",
                "-m",
                "carrier",
                &tree,
            ],
        );
        let storage = GitStorage {
            checkout,
            location: "unused".to_owned(),
            remote: "unused".to_owned(),
            branch: "main".to_owned(),
            state: Mutex::new(GitStorageState { base_commit: None }),
        };
        let id = "ab".repeat(32);
        let read =
            |commit: &str| storage.read_copy_at(commit, ObjectKind::Manifest, &id, |_, _| Ok(()));

        assert!(!read(&commit).unwrap(), "an absent copy is not an error");
        let unknown_commit = "1".repeat(40);
        assert!(
            read(&unknown_commit).is_err(),
            "git ls-tree failing on an unreadable commit must not read as an absent copy"
        );
    }
}
