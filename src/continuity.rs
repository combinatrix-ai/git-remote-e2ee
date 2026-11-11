//! Local state: the machine's continuity floor for each repository root, and
//! the atomic, locked JSON files that hold it and per-checkout progress.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

const FLOOR_FORMAT: u32 = 1;

/// `$XDG_STATE_HOME/git-e2ee`, or `~/.local/state/git-e2ee`. Only binaries
/// call this; the library takes its state directory explicitly.
pub fn default_state_dir() -> Result<PathBuf> {
    let (source, state_home) = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) if !path.is_empty() => ("XDG_STATE_HOME", PathBuf::from(path)),
        _ => (
            "HOME",
            PathBuf::from(
                std::env::var_os("HOME").context("HOME is unset and XDG_STATE_HOME is unset")?,
            )
            .join(".local/state"),
        ),
    };
    if !state_home.is_absolute() {
        bail!("{source} must be an absolute path")
    }
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
        if !state_dir.is_absolute() {
            bail!("continuity state directory must be an absolute path")
        }
        if Path::new(repository_root)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(repository_root)
        {
            bail!("continuity repository root must be one path component")
        }
        let directory = state_dir.join(repository_root);
        #[cfg(unix)]
        let directory = secure_state_directory(&directory)?;
        #[cfg(not(unix))]
        let directory = {
            crate::persist::create_dir_all_durable(&directory)
                .with_context(|| format!("create {}", directory.display()))?;
            directory
        };
        let path = directory.join("continuity.json");
        #[cfg(unix)]
        check_state_file(&path)?;
        #[cfg(unix)]
        let lock = FileLock::acquire_floor(&path)?;
        #[cfg(not(unix))]
        let lock = FileLock::acquire(&path)?;
        Ok(Self { path, _lock: lock })
    }

    pub fn read(&self) -> Result<Option<ContinuityFloor>> {
        #[cfg(unix)]
        check_state_file(&self.path)?;
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
        #[cfg(unix)]
        {
            let directory = self
                .path
                .parent()
                .context("continuity floor has no directory")?;
            crate::persist::replace_private_file_durably(
                directory,
                "continuity.json",
                &serde_json::to_vec_pretty(&next)?,
            )?;
            Ok(())
        }
        #[cfg(not(unix))]
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
        Self::acquire_with_mode(path, false)
    }

    #[cfg(unix)]
    fn acquire_floor(path: &Path) -> Result<Self> {
        Self::acquire_with_mode(path, true)
    }

    fn acquire_with_mode(path: &Path, private: bool) -> Result<Self> {
        let lock_path = path.with_extension("json.lock");
        #[cfg(unix)]
        if private {
            check_state_file(&lock_path)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let file = options
            .open(&lock_path)
            .with_context(|| format!("open lock {}", lock_path.display()))?;
        #[cfg(unix)]
        if private {
            check_opened_state_file(&file, &lock_path)?;
        }
        FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn secure_state_directory(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    check_original_state_path(path)?;
    let mut missing = Vec::new();
    let mut existing = path.to_path_buf();
    let mut current = loop {
        match fs::canonicalize(&existing) {
            Ok(canonical) => break canonical,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = existing
                    .file_name()
                    .context("continuity state path has no existing ancestor")?;
                missing.push(name.to_os_string());
                existing.pop();
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("resolve continuity path {}", existing.display()));
            }
        }
    };
    check_state_directory_chain(&current)?;
    for name in missing.into_iter().rev() {
        current.push(name);
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&current) {
            Ok(()) => crate::persist::sync_directory(
                current.parent().context("continuity state has no parent")?,
            )?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create continuity path {}", current.display()));
            }
        }
        check_state_directory_chain(&current)?;
    }
    let canonical = fs::canonicalize(&current)?;
    check_state_directory_chain(&canonical)?;
    Ok(canonical)
}

#[cfg(unix)]
fn check_original_state_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let user = rustix::process::geteuid().as_raw();
    let mut unresolved = path.to_path_buf();
    let mut links_followed = 0;
    loop {
        if unresolved
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            bail!("continuity state path contains an unsafe component")
        }
        let mut prefix = PathBuf::new();
        let mut expanded = None;
        for component in unresolved.components() {
            prefix.push(component.as_os_str());
            let metadata = match fs::symlink_metadata(&prefix) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect continuity path {}", prefix.display()));
                }
            };
            if metadata.file_type().is_symlink() {
                if metadata.uid() != 0 && metadata.uid() != user {
                    bail!(
                        "continuity path {} is a link owned by another user",
                        prefix.display()
                    )
                }
                check_state_acl(&prefix, true)?;
                links_followed += 1;
                if links_followed > 40 {
                    bail!("continuity state path has too many symbolic links")
                }
                let target = fs::read_link(&prefix)?;
                let suffix = unresolved.strip_prefix(&prefix)?;
                let target = if target.is_absolute() {
                    target
                } else {
                    prefix
                        .parent()
                        .context("continuity state link has no parent")?
                        .join(target)
                };
                expanded = Some(target.join(suffix));
                break;
            } else {
                check_state_directory_metadata(&metadata, &prefix, user)?;
            }
        }
        match expanded {
            Some(path) => unresolved = path,
            None => return Ok(()),
        }
    }
}

#[cfg(unix)]
fn check_state_directory_chain(directory: &Path) -> Result<()> {
    let user = rustix::process::geteuid().as_raw();
    for path in directory.ancestors() {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect continuity directory {}", path.display()))?;
        check_state_directory_metadata(&metadata, path, user)?;
    }
    Ok(())
}

#[cfg(unix)]
fn check_state_directory_metadata(metadata: &fs::Metadata, path: &Path, user: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode();
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0 && metadata.uid() != user
        || mode & 0o022 != 0 && mode & 0o1000 == 0
    {
        bail!(
            "continuity directory {} can be replaced by another user",
            path.display()
        )
    }
    check_state_acl(path, false)?;
    Ok(())
}

#[cfg(unix)]
fn check_state_file(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    check_state_file_metadata(&metadata, path)
}

#[cfg(unix)]
fn check_opened_state_file(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let opened = file.metadata()?;
    check_state_file_metadata(&opened, path)?;
    let named = fs::symlink_metadata(path)?;
    check_state_file_metadata(&named, path)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        bail!("continuity file {} changed while opening", path.display())
    }
    Ok(())
}

#[cfg(unix)]
fn check_state_file_metadata(metadata: &fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        bail!(
            "continuity file {} is writable by another user",
            path.display()
        )
    }
    check_state_acl(path, false)?;
    Ok(())
}

#[cfg(unix)]
fn check_state_acl(path: &Path, is_link: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos_acl::reject_allow_entries(path, is_link)?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (path, is_link);
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos_acl {
    use std::ffi::{CString, c_int, c_void};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use anyhow::{Context, Result, bail};

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_ALLOW: c_int = 1;

    unsafe extern "C" {
        fn acl_get_file(path: *const i8, kind: c_int) -> *mut c_void;
        fn acl_get_link_np(path: *const i8, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_free(acl: *mut c_void) -> c_int;
    }

    pub(super) fn reject_allow_entries(path: &Path, is_link: bool) -> Result<()> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        let acl = unsafe {
            if is_link {
                acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED)
            } else {
                acl_get_file(name.as_ptr(), ACL_TYPE_EXTENDED)
            }
        };
        if acl.is_null() {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error).with_context(|| format!("inspect ACL for {}", path.display()));
        }
        let result = (|| {
            let mut entry = std::ptr::null_mut();
            let mut id = ACL_FIRST_ENTRY;
            loop {
                let status = unsafe { acl_get_entry(acl, id, &mut entry) };
                if status == -1 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::InvalidInput {
                        break;
                    }
                    return Err(error)
                        .with_context(|| format!("inspect ACL for {}", path.display()));
                }
                if status != 0 {
                    bail!("unexpected ACL entry status for {}", path.display())
                }
                let mut tag = 0;
                if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("inspect ACL for {}", path.display()));
                }
                if tag == ACL_EXTENDED_ALLOW {
                    bail!(
                        "continuity path {} grants access through an ACL",
                        path.display()
                    )
                }
                id = ACL_NEXT_ENTRY;
            }
            Ok(())
        })();
        unsafe { acl_free(acl) };
        result
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
    let (Some(directory), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        bail!("state path {} has no parent or file name", path.display())
    };
    crate::persist::replace_file_durably(directory, name, &serde_json::to_vec_pretty(value)?)?;
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
    fn relative_state_directory_cannot_create_a_second_floor() {
        let error = FloorGuard::acquire(Path::new("relative-state"), ROOT)
            .err()
            .expect("relative state directory must fail");
        assert!(format!("{error:#}").contains("must be an absolute path"));
    }

    #[cfg(unix)]
    #[test]
    fn new_floor_paths_stay_private_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let state_dir = temporary.path().join("state");
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "continuity::tests::permissive_umask_floor_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_PRIVATE_FLOOR_STATE_DIR", &state_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let floor = state_dir.join(ROOT).join("continuity.json");
        for directory in [&state_dir, &state_dir.join(ROOT)] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for file in [&floor, &floor.with_extension("json.lock")] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn permissive_umask_floor_worker() {
        let Some(state_dir) = env::var_os("E2EE_TEST_PRIVATE_FLOOR_STATE_DIR") else {
            return;
        };
        unsafe { libc::umask(0) };
        testing_write_floor(Path::new(&state_dir), ROOT, "head-1", 1).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_writable_or_symbolic_floor_paths_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn mode(path: &Path, permissions: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(permissions)).unwrap();
        }

        let temporary = tempfile::tempdir().unwrap();
        let ancestor = temporary.path().join("ancestor");
        let state_dir = ancestor.join("state");
        let floor = testing_write_floor(&state_dir, ROOT, "head-1", 1).unwrap();
        let lock = floor.with_extension("json.lock");
        for directory in [&ancestor, &state_dir, floor.parent().unwrap()] {
            mode(directory, 0o777);
            assert!(
                FloorGuard::acquire(&state_dir, ROOT)
                    .err()
                    .expect("writable directory must fail")
                    .to_string()
                    .contains("can be replaced")
            );
            mode(directory, 0o700);
        }
        for file in [&floor, &lock] {
            mode(file, 0o666);
            assert!(
                FloorGuard::acquire(&state_dir, ROOT)
                    .err()
                    .expect("writable file must fail")
                    .to_string()
                    .contains("writable by another user")
            );
            mode(file, 0o600);
        }

        mode(&state_dir, 0o755);
        mode(floor.parent().unwrap(), 0o755);
        mode(&floor, 0o644);
        mode(&lock, 0o644);
        assert_eq!(
            FloorGuard::acquire(&state_dir, ROOT)
                .unwrap()
                .read()
                .unwrap()
                .unwrap()
                .generation,
            1
        );

        let trusted_alias = temporary.path().join("trusted-alias");
        symlink(&state_dir, &trusted_alias).unwrap();
        assert_eq!(
            FloorGuard::acquire(&trusted_alias, ROOT)
                .unwrap()
                .read()
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        let shared = temporary.path().join("shared-parent");
        fs::create_dir(&shared).unwrap();
        mode(&shared, 0o777);
        symlink(&state_dir, shared.join("state")).unwrap();
        assert!(
            FloorGuard::acquire(&shared.join("state"), ROOT)
                .err()
                .expect("replaceable alias must fail")
                .to_string()
                .contains("can be replaced")
        );

        let nested_alias = temporary.path().join("nested-alias");
        symlink(shared.join("redirect"), &nested_alias).unwrap();
        symlink(&state_dir, shared.join("redirect")).unwrap();
        assert!(
            FloorGuard::acquire(&nested_alias, ROOT)
                .err()
                .expect("link through a replaceable intermediate must fail")
                .to_string()
                .contains("can be replaced")
        );

        let other = temporary.path().join("other-floor");
        fs::write(&other, "{}").unwrap();
        fs::remove_file(&floor).unwrap();
        symlink(&other, &floor).unwrap();
        assert!(FloorGuard::acquire(&state_dir, ROOT).is_err());

        fs::remove_file(&floor).unwrap();
        fs::remove_file(&lock).unwrap();
        symlink(&other, &lock).unwrap();
        assert!(FloorGuard::acquire(&state_dir, ROOT).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn acl_write_grants_cannot_reset_the_floor() {
        fn allow_write(path: &Path, grant: &str) {
            let output = Command::new("chmod")
                .args(["+a", grant])
                .arg(path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        for target in ["directory", "floor", "lock"] {
            let temporary = tempfile::tempdir().unwrap();
            let state_dir = temporary.path().join("state");
            let floor = testing_write_floor(&state_dir, ROOT, "head-1", 1).unwrap();
            let protected = match target {
                "directory" => state_dir,
                "floor" => floor.clone(),
                "lock" => floor.with_extension("json.lock"),
                _ => unreachable!(),
            };
            let grant = if target == "directory" {
                "everyone allow add_file,delete_child"
            } else {
                "everyone allow write"
            };
            allow_write(&protected, grant);
            assert!(
                FloorGuard::acquire(&temporary.path().join("state"), ROOT)
                    .err()
                    .expect("ACL write grant must fail")
                    .to_string()
                    .contains("grants access through an ACL")
            );
        }
    }

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
