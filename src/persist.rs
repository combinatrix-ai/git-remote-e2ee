//! Durable directory publication for filesystem state.
//!
//! Callers flush file contents, publish the name, then flush the parent
//! directory. A failure from any of those steps is returned. Success is not
//! reported when the directory flush fails.
//!
//! `HEAD` and client state are renamed within one directory. Immutable objects
//! are hard-linked from `.staging` to `objects/<prefix>/` — different
//! directories on the same filesystem, not a same-directory link. Newly
//! created directories are flushed from the new directory through the deepest
//! ancestor that already existed. Ancestors above that directory are not
//! flushed.
//!
//! On Unix the directory flush is `File::open` plus `sync_all` (`fsync`).
//! On Windows, `File::open` uses an access mask that cannot flush a directory:
//! a handle opened with access 0 or `GENERIC_READ` accepts `CreateFile` and
//! then `FlushFileBuffers` fails with `ERROR_ACCESS_DENIED` (os error 5).
//! The flush that succeeds on Windows 11 NTFS, including a limited interactive
//! token, is `GENERIC_WRITE` (`0x40000000`), share mode 7
//! (`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`),
//! `OPEN_EXISTING`, and `FILE_FLAG_BACKUP_SEMANTICS` (`0x02000000`).
//! Opening the directory is not treated as proof that the flush worked;
//! `sync_all` (`FlushFileBuffers`) errors propagate.
//!
//! This asks the operating system to commit the directory entry. It does not
//! prove that a particular disk honoured the flush, and it is not a substitute
//! for a hard power cut. See `DURABILITY.md`.

use std::io;
use std::path::Path;

/// File contents have been flushed. The destination name has not been published.
pub(crate) const STAGE_AFTER_FILE_FLUSH: &str = "after_file_flush";
/// Rename or hard link has returned. The parent directory has not been flushed.
pub(crate) const STAGE_AFTER_NAME_PUBLISH: &str = "after_name_publish";
/// The persistence function has returned success to its caller.
/// Emitted by the power-cut harness after that return, not by library paths.
#[cfg(test)]
pub(crate) const STAGE_AFTER_ACKNOWLEDGE: &str = "after_acknowledge";

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let file = std::fs::File::open(path)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(windows)]
    {
        sync_directory_windows(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        compile_error!("directory sync is implemented for Unix and Windows only");
    }
}

#[cfg(windows)]
fn sync_directory_windows(path: &Path) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    // No create/truncate flags: Rust maps that to OPEN_EXISTING (3).
    // access_mode replaces read/write flags; do not also set GENERIC_READ.
    let mut options = OpenOptions::new();
    options
        .access_mode(GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let file = options.open(path)?;
    file.sync_all()?;
    Ok(())
}

/// Create `path` and any missing parents.
///
/// Relative paths are joined to the process working directory. `.` and `..`
/// stay in the path and are resolved by the operating system, not removed
/// lexically. An empty path is rejected.
///
/// Each directory created by this call is flushed, and so is the deepest
/// ancestor that already existed, because that directory gained a new child
/// name. Ancestors above it are not flushed. If `path` already exists, nothing
/// is flushed.
///
/// On failure, directories created by this call are removed when possible so a
/// retry can flush the ancestor again. If they cannot be removed, the tree is
/// ambiguous: a later call sees them and does not flush ancestors. That does
/// not make a previously unflushed entry durable. A failed call is
/// unacknowledged and must be revalidated.
pub(crate) fn create_dir_all_durable(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty directory path",
        ));
    }
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing = Vec::new();
    let mut cursor = anchored;
    let preexisting = loop {
        if cursor.exists() {
            break cursor;
        }
        let Some(parent) = cursor
            .parent()
            .map(Path::to_path_buf)
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no existing ancestor for {}", path.display()),
            ));
        };
        missing.push(cursor);
        cursor = parent;
    };
    if !preexisting.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is not a directory", preexisting.display()),
        ));
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut created = Vec::new();
    for directory in missing.iter().rev() {
        match std::fs::create_dir(directory) {
            Ok(()) => created.push(directory.clone()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                remove_created_directories(&created);
                return Err(error);
            }
        }
    }
    if let Err(error) = flush_created_directories(&missing, &preexisting) {
        remove_created_directories(&created);
        return Err(error);
    }
    Ok(())
}

fn flush_created_directories(missing: &[std::path::PathBuf], preexisting: &Path) -> io::Result<()> {
    for directory in missing {
        sync_directory(directory)?;
    }
    sync_directory(preexisting)?;
    Ok(())
}

fn remove_created_directories(created: &[std::path::PathBuf]) {
    for directory in created.iter().rev() {
        let _ = std::fs::remove_dir(directory);
    }
}

pub(crate) fn durability_checkpoint(stage: &str) {
    #[cfg(test)]
    {
        let hook = DURABILITY_HOOK.with(|slot| slot.borrow().clone());
        if let Some(hook) = hook {
            hook(stage);
        }
    }
    #[cfg(not(test))]
    {
        let _ = stage;
    }
}

#[cfg(test)]
type DurabilityHook = std::sync::Arc<dyn Fn(&str)>;

#[cfg(test)]
thread_local! {
    static DURABILITY_HOOK: std::cell::RefCell<Option<DurabilityHook>> = std::cell::RefCell::new(None);
}

/// Installs a same-thread observer for persistence stages.
///
/// Compiled only into test builds. Production binaries have no hook state and
/// do not read the environment.
#[cfg(test)]
pub(crate) fn set_durability_hook(hook: Option<DurabilityHook>) {
    DURABILITY_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{SocketAddr, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::{
        STAGE_AFTER_ACKNOWLEDGE, STAGE_AFTER_FILE_FLUSH, STAGE_AFTER_NAME_PUBLISH,
        create_dir_all_durable, set_durability_hook, sync_directory,
    };
    use crate::crypto::object_id;
    use crate::repository::testing_write_client_state;
    use crate::storage::{FilesystemStorage, ObjectKind, Storage};

    const CLIENT_V1: &[u8] = b"e2ee-durability-client-v1";
    const CLIENT_V2: &[u8] = b"e2ee-durability-client-v2";
    const HEAD_V1: &[u8] = b"e2ee-durability-head-v1";
    const HEAD_V2: &[u8] = b"e2ee-durability-head-v2";
    const OBJECT_V1: &[u8] = b"e2ee-durability-object-v1";
    const OBJECT_V2: &[u8] = b"e2ee-durability-object-v2";
    const ROOT_LABEL: &str = "durability-fixture";

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            set_durability_hook(None);
        }
    }

    fn install_hook(hook: impl Fn(&str) + 'static) -> HookGuard {
        set_durability_hook(Some(Arc::new(hook)));
        HookGuard
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Observed {
        Old,
        New,
    }

    impl Observed {
        fn as_str(self) -> &'static str {
            match self {
                Self::Old => "old",
                Self::New => "new",
            }
        }
    }

    fn client_ids() -> (String, String) {
        (object_id(CLIENT_V1), object_id(CLIENT_V2))
    }

    fn head_ids() -> (String, String) {
        (object_id(HEAD_V1), object_id(HEAD_V2))
    }

    fn object_ids() -> (String, String) {
        (object_id(OBJECT_V1), object_id(OBJECT_V2))
    }

    fn op_dir(fixture: &Path, op: &str) -> PathBuf {
        fixture.join(match op {
            "client_state" => "client",
            "head" => "head",
            "object" => "object-store",
            other => panic!("unknown durability op {other}"),
        })
    }

    fn client_path(fixture: &Path) -> PathBuf {
        op_dir(fixture, "client_state").join("state.json")
    }

    fn object_file(root: &Path, id: &str) -> PathBuf {
        root.join("objects").join(&id[..2]).join(id)
    }

    fn reset_dir(path: &Path) {
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
        create_dir_all_durable(path).unwrap();
    }

    fn json_string(value: &serde_json::Value, field: &str) -> Result<String, String> {
        value
            .get(field)
            .and_then(|item| item.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("client state is missing string field {field}"))
    }

    fn classify_client(path: &Path) -> Result<Observed, String> {
        let bytes = fs::read(path).map_err(|error| format!("read client state: {error}"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("client state is not complete JSON: {error}"))?;
        let head = json_string(&value, "head_id")?;
        let root = json_string(&value, "repository_root")?;
        let generation = value
            .get("generation")
            .and_then(|item| item.as_u64())
            .ok_or("client state is missing generation")?;
        let imported = value
            .get("imported_generation")
            .and_then(|item| item.as_u64())
            .ok_or("client state is missing imported_generation")?;
        if imported != generation || root != ROOT_LABEL {
            return Err("client state fields are not a complete baseline or successor".into());
        }
        let (v1, v2) = client_ids();
        if head == v1 && generation == 1 {
            Ok(Observed::Old)
        } else if head == v2 && generation == 2 {
            Ok(Observed::New)
        } else {
            Err(format!(
                "client state is neither baseline nor successor (head {head}, generation {generation})"
            ))
        }
    }

    fn classify_head(root: &Path) -> Result<Observed, String> {
        let (v1, v2) = head_ids();
        match FilesystemStorage::new(root).read_head() {
            Ok(Some(id)) if id == v1 => Ok(Observed::Old),
            Ok(Some(id)) if id == v2 => Ok(Observed::New),
            Ok(Some(id)) => Err(format!("HEAD is neither baseline nor successor: {id}")),
            Ok(None) => Err("HEAD is missing".into()),
            Err(error) => Err(format!("HEAD is not a complete id: {error}")),
        }
    }

    fn classify_object(root: &Path) -> Result<Observed, String> {
        let (v1, v2) = object_ids();
        let baseline = fs::read(object_file(root, &v1))
            .map_err(|error| format!("read baseline object: {error}"))?;
        if baseline != OBJECT_V1 {
            return Err("baseline immutable object was overwritten or truncated".into());
        }
        match fs::read(object_file(root, &v2)) {
            Ok(bytes) if bytes == OBJECT_V2 => Ok(Observed::New),
            Ok(_) => Err("successor object is not the complete fixture payload".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Observed::Old),
            Err(error) => Err(format!("read successor object: {error}")),
        }
    }

    fn classify(op: &str, fixture: &Path) -> Result<Observed, String> {
        match op {
            "client_state" => classify_client(&client_path(fixture)),
            "head" => classify_head(&op_dir(fixture, "head")),
            "object" => classify_object(&op_dir(fixture, "object")),
            other => Err(format!("unknown durability op {other}")),
        }
    }

    fn expect_observation(op: &str, stage: &str, fixture: &Path) -> Result<Observed, String> {
        let observed = classify(op, fixture)?;
        match stage {
            STAGE_AFTER_FILE_FLUSH | STAGE_AFTER_NAME_PUBLISH => Ok(observed),
            STAGE_AFTER_ACKNOWLEDGE => {
                if observed == Observed::New {
                    Ok(observed)
                } else {
                    Err("after acknowledge, state is still the baseline".into())
                }
            }
            other => Err(format!("unknown durability stage {other}")),
        }
    }

    fn setup_op(op: &str, fixture: &Path) {
        match op {
            "client_state" => {
                let dir = op_dir(fixture, op);
                reset_dir(&dir);
                let (v1, _) = client_ids();
                testing_write_client_state(&dir.join("state.json"), &v1, 1).unwrap();
            }
            "head" => {
                let dir = op_dir(fixture, op);
                reset_dir(&dir);
                let (v1, _) = head_ids();
                FilesystemStorage::new(&dir)
                    .compare_and_swap_head(None, &v1)
                    .unwrap();
            }
            "object" => {
                let dir = op_dir(fixture, op);
                reset_dir(&dir);
                let (v1, _) = object_ids();
                FilesystemStorage::new(&dir)
                    .put_object_if_absent(ObjectKind::Pack, &v1, OBJECT_V1)
                    .unwrap();
            }
            other => panic!("unknown durability op {other}"),
        }
    }

    fn require_baseline(op: &str, fixture: &Path) {
        match classify(op, fixture) {
            Ok(Observed::Old) => {}
            Ok(Observed::New) => panic!(
                "{op} fixture is already the successor; run mode=setup before another mutate"
            ),
            Err(error) => {
                panic!("{op} fixture is not a complete baseline ({error}); run mode=setup")
            }
        }
    }

    fn mutate_op(op: &str, fixture: &Path) {
        match op {
            "client_state" => {
                let (_, v2) = client_ids();
                testing_write_client_state(&client_path(fixture), &v2, 2).unwrap();
            }
            "head" => {
                let (v1, v2) = head_ids();
                FilesystemStorage::new(op_dir(fixture, op))
                    .compare_and_swap_head(Some(&v1), &v2)
                    .unwrap();
            }
            "object" => {
                let (_, v2) = object_ids();
                FilesystemStorage::new(op_dir(fixture, op))
                    .put_object_if_absent(ObjectKind::Pack, &v2, OBJECT_V2)
                    .unwrap();
            }
            other => panic!("unknown durability op {other}"),
        }
    }

    fn checkpoint_line(op: &str, stage: &str) -> String {
        let line = format!("E2EE_DURABILITY_CHECKPOINT op={op} stage={stage}\n");
        assert!(
            line.len() <= 512,
            "checkpoint line is {} bytes; listener accepts at most 512",
            line.len()
        );
        line
    }

    fn arm_power_cut_wait(op: &str, stage: &str, stream: TcpStream) -> HookGuard {
        let selected = stage.to_owned();
        let op = op.to_owned();
        let stream = Arc::new(Mutex::new(stream));
        install_hook(move |reached| {
            if reached != selected {
                return;
            }
            let line = checkpoint_line(&op, reached);
            let mut socket = stream.lock().expect("checkpoint socket");
            socket.write_all(line.as_bytes()).expect("write checkpoint");
            socket.flush().expect("flush checkpoint");
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        })
    }

    fn external_checkpoint_addr(value: Option<String>) -> SocketAddr {
        let value = value.unwrap_or_else(|| {
            panic!("E2EE_DURABILITY_TCP is required for mutate; there is no loopback default")
        });
        let socket_addr: SocketAddr = value
            .parse()
            .unwrap_or_else(|error| panic!("invalid E2EE_DURABILITY_TCP {value}: {error}"));
        if socket_addr.ip().is_loopback() {
            panic!(
                "E2EE_DURABILITY_TCP must be the external listener (172.18.0.1:18765), not {socket_addr}"
            );
        }
        socket_addr
    }

    fn run_power_cut_harness() {
        let fixture = std::env::var("E2EE_DURABILITY_FIXTURE").unwrap_or_else(|_| {
            panic!(
                "E2EE_DURABILITY_FIXTURE is required (isolated directory; never a Vault or key path)"
            )
        });
        let op = std::env::var("E2EE_DURABILITY_OP")
            .unwrap_or_else(|_| panic!("E2EE_DURABILITY_OP must be client_state, head, or object"));
        let mode = std::env::var("E2EE_DURABILITY_MODE")
            .unwrap_or_else(|_| panic!("E2EE_DURABILITY_MODE must be setup, mutate, or check"));
        let fixture = PathBuf::from(fixture);
        create_dir_all_durable(&fixture).unwrap();
        match mode.as_str() {
            "setup" => {
                setup_op(&op, &fixture);
                println!("E2EE_DURABILITY_SETUP op={op} result=pass");
            }
            "check" => {
                let stage = std::env::var("E2EE_DURABILITY_STAGE").unwrap_or_else(|_| {
                    panic!(
                        "E2EE_DURABILITY_STAGE must be after_file_flush, after_name_publish, or after_acknowledge"
                    )
                });
                match expect_observation(&op, &stage, &fixture) {
                    Ok(observed) => println!(
                        "E2EE_DURABILITY_CHECK op={op} stage={stage} result=pass observed={}",
                        observed.as_str()
                    ),
                    Err(error) => panic!(
                        "E2EE_DURABILITY_CHECK op={op} stage={stage} result=fail reason={error}"
                    ),
                }
            }
            "mutate" => {
                let stage = std::env::var("E2EE_DURABILITY_STAGE").unwrap_or_else(|_| {
                    panic!(
                        "E2EE_DURABILITY_STAGE must be after_file_flush, after_name_publish, or after_acknowledge"
                    )
                });
                match stage.as_str() {
                    STAGE_AFTER_FILE_FLUSH | STAGE_AFTER_NAME_PUBLISH | STAGE_AFTER_ACKNOWLEDGE => {
                    }
                    other => panic!("unknown durability stage {other}"),
                }
                let addr = external_checkpoint_addr(std::env::var("E2EE_DURABILITY_TCP").ok());
                require_baseline(&op, &fixture);
                let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(30))
                    .unwrap_or_else(|error| {
                        panic!("connect to {addr} before mutation failed: {error}")
                    });
                println!("E2EE_DURABILITY_CONNECTED op={op} stage={stage} addr={addr}");
                let _ = std::io::stdout().flush();
                let _guard = arm_power_cut_wait(&op, &stage, stream);
                mutate_op(&op, &fixture);
                super::durability_checkpoint(STAGE_AFTER_ACKNOWLEDGE);
                panic!("durability stage {stage} was not reached; no power-cut wait was entered");
            }
            other => panic!("unknown durability mode {other}"),
        }
    }

    #[test]
    fn empty_directory_path_is_rejected() {
        let error = create_dir_all_durable(Path::new("")).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn directory_sync_propagates_missing_directory() {
        let missing =
            std::env::temp_dir().join(format!("e2ee-missing-dir-sync-{}", std::process::id()));
        let _ = fs::remove_dir(&missing);
        assert!(sync_directory(&missing).is_err());
    }

    #[test]
    fn durable_create_stops_at_the_preexisting_ancestor_and_rejects_a_file() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("git-remote-e2ee").join("origin");
        create_dir_all_durable(&nested).unwrap();
        assert!(nested.is_dir());
        create_dir_all_durable(&nested).unwrap();
        let blocking = root.path().join("not-a-directory");
        fs::write(&blocking, b"x").unwrap();
        assert!(create_dir_all_durable(&blocking.join("child")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn read_only_directory_flush_fails_and_write_handle_succeeds() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let directory = tempfile::tempdir().unwrap();
        let mut read_only = OpenOptions::new();
        read_only
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        let file = read_only.open(directory.path()).unwrap();
        assert!(
            file.sync_all().is_err(),
            "GENERIC_READ directory handle must not report a successful flush"
        );
        sync_directory(directory.path()).unwrap();
    }

    #[test]
    fn checkpoint_endpoint_rejects_a_missing_or_loopback_listener() {
        assert!(std::panic::catch_unwind(|| external_checkpoint_addr(None)).is_err());
        assert!(
            std::panic::catch_unwind(|| {
                external_checkpoint_addr(Some("127.0.0.1:18765".to_owned()))
            })
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| external_checkpoint_addr(Some("localhost:18765".into())))
                .is_err()
        );
        let addr = external_checkpoint_addr(Some("172.18.0.1:18765".to_owned()));
        assert_eq!(addr.to_string(), "172.18.0.1:18765");
    }

    #[test]
    fn client_state_and_head_replace_repeatedly() {
        let fixture = tempfile::tempdir().unwrap();
        setup_op("client_state", fixture.path());
        let path = client_path(fixture.path());
        let second = object_id(b"e2ee-durability-client-v2");
        let third = object_id(b"e2ee-durability-client-v3");
        testing_write_client_state(&path, &second, 2).unwrap();
        testing_write_client_state(&path, &third, 3).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["head_id"], third);
        assert_eq!(value["generation"], 3);

        setup_op("head", fixture.path());
        let root = op_dir(fixture.path(), "head");
        let (first, second) = head_ids();
        let third = object_id(b"e2ee-durability-head-v3");
        let storage = FilesystemStorage::new(&root);
        storage
            .compare_and_swap_head(Some(&first), &second)
            .unwrap();
        storage
            .compare_and_swap_head(Some(&second), &third)
            .unwrap();
        assert_eq!(
            storage.read_head().unwrap().as_deref(),
            Some(third.as_str())
        );
    }

    #[test]
    fn client_state_checkpoints_see_old_bytes_then_new_bytes() {
        let fixture = tempfile::tempdir().unwrap();
        setup_op("client_state", fixture.path());
        let path = client_path(fixture.path());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let watch = path.clone();
        let _guard = install_hook(move |stage| {
            let bytes = fs::read(&watch).ok();
            record.lock().unwrap().push((stage.to_owned(), bytes));
        });
        mutate_op("client_state", fixture.path());
        drop(_guard);
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.iter()
                .map(|(stage, _)| stage.as_str())
                .collect::<Vec<_>>(),
            vec![STAGE_AFTER_FILE_FLUSH, STAGE_AFTER_NAME_PUBLISH]
        );
        assert_eq!(classify_bytes_head(&seen[0].1), Observed::Old);
        assert_eq!(classify_bytes_head(&seen[1].1), Observed::New);
        assert_eq!(classify_client(&path).unwrap(), Observed::New);
    }

    fn classify_bytes_head(bytes: &Option<Vec<u8>>) -> Observed {
        let bytes = bytes.as_ref().expect("client state missing at checkpoint");
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let head = value["head_id"].as_str().unwrap();
        let (v1, v2) = client_ids();
        if head == v1 {
            Observed::Old
        } else if head == v2 {
            Observed::New
        } else {
            panic!("unexpected head at checkpoint");
        }
    }

    #[test]
    fn head_checkpoints_see_old_name_then_new_name() {
        let fixture = tempfile::tempdir().unwrap();
        setup_op("head", fixture.path());
        let root = op_dir(fixture.path(), "head");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let watch = root.clone();
        let _guard = install_hook(move |stage| {
            let observed = classify_head(&watch).unwrap();
            record.lock().unwrap().push((stage.to_owned(), observed));
        });
        mutate_op("head", fixture.path());
        drop(_guard);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], (STAGE_AFTER_FILE_FLUSH.to_owned(), Observed::Old));
        assert_eq!(
            seen[1],
            (STAGE_AFTER_NAME_PUBLISH.to_owned(), Observed::New)
        );
        assert_eq!(classify_head(&root).unwrap(), Observed::New);
    }

    #[test]
    fn object_checkpoint_preserves_baseline_and_publishes_successor_by_link() {
        let fixture = tempfile::tempdir().unwrap();
        setup_op("object", fixture.path());
        let root = op_dir(fixture.path(), "object");
        let (v1, v2) = object_ids();
        let before = fs::read(object_file(&root, &v1)).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let watch = root.clone();
        let successor = v2.clone();
        let _guard = install_hook(move |stage| {
            let path = object_file(&watch, &successor);
            let bytes = fs::read(&path).ok();
            record.lock().unwrap().push((stage.to_owned(), bytes));
        });
        mutate_op("object", fixture.path());
        drop(_guard);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].0, STAGE_AFTER_FILE_FLUSH);
        assert!(seen[0].1.is_none());
        assert_eq!(seen[1].0, STAGE_AFTER_NAME_PUBLISH);
        assert_eq!(seen[1].1.as_deref(), Some(OBJECT_V2));
        assert_eq!(fs::read(object_file(&root, &v1)).unwrap(), before);
        assert_eq!(fs::read(object_file(&root, &v2)).unwrap(), OBJECT_V2);
        FilesystemStorage::new(&root)
            .put_object_if_absent(ObjectKind::Pack, &v1, OBJECT_V1)
            .unwrap();
        assert_eq!(fs::read(object_file(&root, &v1)).unwrap(), before);
        fs::write(object_file(&root, &v1), b"tampered").unwrap();
        assert!(
            FilesystemStorage::new(&root)
                .put_object_if_absent(ObjectKind::Pack, &v1, OBJECT_V1)
                .is_err()
        );
        assert_eq!(fs::read(object_file(&root, &v1)).unwrap(), b"tampered");
    }

    #[test]
    fn power_cut_checker_accepts_complete_old_or_new_before_ack_and_only_new_after() {
        let fixture = tempfile::tempdir().unwrap();
        setup_op("client_state", fixture.path());
        assert_eq!(
            expect_observation("client_state", STAGE_AFTER_FILE_FLUSH, fixture.path()).unwrap(),
            Observed::Old
        );
        assert_eq!(
            expect_observation("client_state", STAGE_AFTER_NAME_PUBLISH, fixture.path()).unwrap(),
            Observed::Old
        );
        assert!(
            expect_observation("client_state", STAGE_AFTER_ACKNOWLEDGE, fixture.path()).is_err()
        );
        fs::write(client_path(fixture.path()), b"{").unwrap();
        assert!(
            expect_observation("client_state", STAGE_AFTER_FILE_FLUSH, fixture.path()).is_err()
        );

        setup_op("head", fixture.path());
        assert_eq!(
            expect_observation("head", STAGE_AFTER_NAME_PUBLISH, fixture.path()).unwrap(),
            Observed::Old
        );
        mutate_op("head", fixture.path());
        assert_eq!(
            expect_observation("head", STAGE_AFTER_ACKNOWLEDGE, fixture.path()).unwrap(),
            Observed::New
        );

        setup_op("object", fixture.path());
        assert_eq!(
            expect_observation("object", STAGE_AFTER_FILE_FLUSH, fixture.path()).unwrap(),
            Observed::Old
        );
        mutate_op("object", fixture.path());
        assert_eq!(
            expect_observation("object", STAGE_AFTER_ACKNOWLEDGE, fixture.path()).unwrap(),
            Observed::New
        );
        let (v1, _) = object_ids();
        fs::write(object_file(&op_dir(fixture.path(), "object"), &v1), b"x").unwrap();
        assert!(expect_observation("object", STAGE_AFTER_ACKNOWLEDGE, fixture.path()).is_err());
    }

    /// External Windows hard-power-cut entry point. Ignored so `cargo test` does not block.
    ///
    /// The wait inside `mode=mutate` is the window for a QEMU hard power cut. Killing the
    /// process is not a power cut and is not what this harness is for.
    #[test]
    #[ignore = "blocks until an external hard power cut; see DURABILITY.md"]
    fn durability_power_cut_harness() {
        run_power_cut_harness();
    }
}
