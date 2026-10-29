//! Local state: the machine's continuity floor for each repository root, and
//! the atomic, locked JSON files that hold it and per-checkout progress.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

const FLOOR_FORMAT: u32 = 1;

/// `$XDG_STATE_HOME/git-e2ee`, or `~/.local/state/git-e2ee`. Only binaries
/// call this; the library takes its state directory explicitly.
pub fn default_state_dir() -> Result<PathBuf> {
    let state_home = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            std::env::var_os("HOME").context("HOME is unset and XDG_STATE_HOME is unset")?,
        )
        .join(".local/state"),
    };
    Ok(state_home.join("git-e2ee"))
}

/// The newest authenticated head this machine has accepted for one
/// repository root. Storage must stay on a chain through it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuityFloor {
    format_version: u32,
    pub repository_root: String,
    pub head_id: String,
    pub generation: u64,
    pub policy_generation: u64,
}

impl ContinuityFloor {
    pub fn at(head_id: &str, manifest: &Manifest) -> Self {
        Self {
            format_version: FLOOR_FORMAT,
            repository_root: manifest.repository_root.clone(),
            head_id: head_id.to_owned(),
            generation: manifest.generation,
            policy_generation: manifest.policy_generation,
        }
    }
}

/// Exclusive hold on one root's floor. Every operation that reads or
/// publishes storage state holds it from validation through advancement, so
/// processes on this machine serialize.
pub(crate) struct FloorGuard {
    path: PathBuf,
    _lock: FileLock,
}

impl FloorGuard {
    pub fn acquire(state_dir: &Path, repository_root: &str) -> Result<Self> {
        let directory = state_dir.join(repository_root);
        crate::persist::create_dir_all_durable(&directory)
            .with_context(|| format!("create {}", directory.display()))?;
        let path = directory.join("continuity.json");
        let lock = FileLock::acquire(&path)?;
        Ok(Self { path, _lock: lock })
    }

    pub fn read(&self) -> Result<Option<ContinuityFloor>> {
        let floor: Option<ContinuityFloor> = read_json(&self.path)?;
        if let Some(floor) = &floor
            && floor.format_version != FLOOR_FORMAT
        {
            bail!(
                "unsupported continuity floor format {}",
                floor.format_version
            )
        }
        Ok(floor)
    }

    /// Moves the floor to `next` unless it already stands at a later
    /// generation. A different head at the same generation is a fork.
    pub fn advance(&self, next: ContinuityFloor) -> Result<()> {
        if let Some(previous) = self.read()? {
            if previous.repository_root != next.repository_root {
                bail!("remote repository root changed")
            }
            if previous.generation > next.generation {
                return Ok(());
            }
            if previous.generation == next.generation && previous.head_id != next.head_id {
                bail!("remote manifest history forked from the locally pinned head")
            }
            if next.policy_generation < previous.policy_generation {
                bail!("remote policy rolled back")
            }
            if previous == next {
                return Ok(());
            }
        }
        write_json(&self.path, &next)
    }
}

/// An exclusive advisory lock on a stable sibling of `path`, which writers
/// replace atomically.
pub(crate) struct FileLock {
    _file: File,
}

impl FileLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let lock_path = path.with_extension("json.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;
        FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(contents) => Ok(Some(
            serde_json::from_slice(&contents)
                .with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = path.with_extension(format!("json.{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_FILE_FLUSH);
    fs::rename(&temporary, path)?;
    crate::persist::durability_checkpoint(crate::persist::STAGE_AFTER_NAME_PUBLISH);
    let parent = match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
        None => bail!("state path has no parent"),
    };
    crate::persist::sync_directory(parent)
        .with_context(|| format!("sync directory {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn testing_write_floor(
    state_dir: &Path,
    repository_root: &str,
    head_id: &str,
    generation: u64,
) -> Result<PathBuf> {
    let guard = FloorGuard::acquire(state_dir, repository_root)?;
    guard.advance(ContinuityFloor {
        format_version: FLOOR_FORMAT,
        repository_root: repository_root.to_owned(),
        head_id: head_id.to_owned(),
        generation,
        policy_generation: 1,
    })?;
    Ok(guard.path.clone())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{FloorGuard, testing_write_floor};

    const ROOT: &str = "concurrency-fixture";

    #[test]
    fn concurrent_floor_process_writes_never_lower_or_corrupt_the_floor() {
        let temporary = tempfile::tempdir().unwrap();
        let state_dir = temporary.path().join("state");
        testing_write_floor(&state_dir, ROOT, "head-10", 10).unwrap();
        let release = temporary.path().join("release-old-writer");
        let ready = temporary.path().join("old-writer-ready");
        let executable = env::current_exe().unwrap();

        let older = Command::new(&executable)
            .args([
                "--exact",
                "continuity::tests::floor_process_write_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_FLOOR_STATE_DIR", &state_dir)
            .env("E2EE_TEST_FLOOR_GENERATION", "11")
            .env("E2EE_TEST_FLOOR_READY", &ready)
            .env("E2EE_TEST_FLOOR_RELEASE", &release)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "older writer did not reach its wait point");

        let newer = launch_floor_writer(&executable, &state_dir, 12);
        let newer_output = newer.wait_with_output().unwrap();
        assert!(
            newer_output.status.success(),
            "newer writer failed: {}",
            String::from_utf8_lossy(&newer_output.stderr)
        );
        fs::write(&release, "continue").unwrap();

        let older_output = older.wait_with_output().unwrap();
        assert!(
            older_output.status.success(),
            "older writer failed: {}",
            String::from_utf8_lossy(&older_output.stderr)
        );
        let floor = FloorGuard::acquire(&state_dir, ROOT)
            .unwrap()
            .read()
            .unwrap()
            .unwrap();
        assert_eq!(floor.generation, 12);
        assert_eq!(floor.head_id, "head-12");
    }

    #[test]
    fn floor_process_write_worker() {
        let Ok(state_dir) = env::var("E2EE_TEST_FLOOR_STATE_DIR") else {
            return;
        };
        let generation = env::var("E2EE_TEST_FLOOR_GENERATION")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        if let (Ok(ready), Ok(release)) = (
            env::var("E2EE_TEST_FLOOR_READY"),
            env::var("E2EE_TEST_FLOOR_RELEASE"),
        ) {
            fs::write(&ready, "ready").unwrap();
            let release = Path::new(&release);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !release.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(release.exists(), "parent did not release the older writer");
        }
        testing_write_floor(
            Path::new(&state_dir),
            ROOT,
            &format!("head-{generation}"),
            generation,
        )
        .unwrap();
    }

    fn launch_floor_writer(executable: &Path, state_dir: &Path, generation: u64) -> Child {
        Command::new(executable)
            .args([
                "--exact",
                "continuity::tests::floor_process_write_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_FLOOR_STATE_DIR", state_dir)
            .env("E2EE_TEST_FLOOR_GENERATION", generation.to_string())
            .spawn()
            .unwrap()
    }

    #[test]
    fn a_different_head_at_the_floor_generation_is_a_fork() {
        let temporary = tempfile::tempdir().unwrap();
        testing_write_floor(temporary.path(), ROOT, "head-a", 3).unwrap();
        let error = testing_write_floor(temporary.path(), ROOT, "head-b", 3).unwrap_err();
        assert!(format!("{error:#}").contains("forked"), "{error:#}");
    }
}
