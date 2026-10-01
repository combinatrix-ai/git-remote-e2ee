use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage, Storage};

static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn git_output(repo: &Path, args: &[&str], with_helper: bool) -> Output {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo).args(args);
    if with_helper {
        add_helper_to_path(&mut command);
    }
    command.output().unwrap()
}

fn git(repo: &Path, args: &[&str], with_helper: bool) -> String {
    let output = git_output(repo, args, with_helper);
    assert!(
        output.status.success(),
        "git {:?}: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn add_helper_to_path(command: &mut Command) {
    let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
    let mut paths = vec![helper.parent().unwrap().to_path_buf()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    command.env("PATH", env::join_paths(paths).unwrap());
}

fn initialize_git(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q", "-b", "main"], false);
    git(repo, &["config", "user.name", "Read Only Test"], false);
    git(
        repo,
        &["config", "user.email", "read-only@example.invalid"],
        false,
    );
}

fn commit(repo: &Path, contents: &str, message: &str) -> String {
    fs::write(repo.join("note.md"), contents).unwrap();
    git(repo, &["add", "note.md"], false);
    git(repo, &["commit", "-q", "-m", message], false);
    git(repo, &["rev-parse", "HEAD"], false)
}

fn configure_remote(repo: &Path, name: &str, url: &str, key_path: &Path) {
    git(repo, &["remote", "add", name, url], false);
    git(
        repo,
        &[
            "config",
            &format!("remote.{name}.e2ee-key"),
            key_path.to_str().unwrap(),
        ],
        false,
    );
}

fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, current: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(root, &path, files);
            } else {
                files.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                ));
            }
        }
    }

    let mut files = Vec::new();
    visit(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn exercise_read_only_helper<S: Storage>(
    temporary: &Path,
    storage: S,
    remote_path: &Path,
    remote_url: &str,
) {
    fs::create_dir_all(temporary).unwrap();
    let owner_key_path = temporary.join("owner.key.json");
    let reader_key_path = temporary.join("reader.key.json");
    let owner_key = KeyFile::generate();
    let reader_key = KeyFile::generate_for_repository(owner_key.repository_root.clone()).unwrap();
    owner_key.write_new(&owner_key_path).unwrap();
    reader_key.write_new(&reader_key_path).unwrap();

    let owner = EncryptedRepository::new(storage, owner_key);
    owner.initialize().unwrap();
    let admin_pin = temporary.join("owner.admin-state.json");
    owner.pin_admin_state(&admin_pin).unwrap();
    owner
        .add_device(
            reader_key.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();

    let source = temporary.join("writer");
    initialize_git(&source);
    let first = commit(&source, "initial writer content\n", "initial");
    configure_remote(&source, "private", remote_url, &owner_key_path);
    git(&source, &["push", "private", "main"], true);

    let clone = temporary.join("reader-clone");
    let mut clone_command = Command::new("git");
    clone_command
        .args([
            "-c",
            &format!("e2ee.key={}", reader_key_path.display()),
            "clone",
            "-q",
            remote_url,
        ])
        .arg(&clone);
    add_helper_to_path(&mut clone_command);
    let output = clone_command.output().unwrap();
    assert!(
        output.status.success(),
        "reader clone failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), first);
    assert_eq!(
        fs::read_to_string(clone.join("note.md")).unwrap(),
        "initial writer content\n"
    );

    let second = commit(&source, "fetched writer content\n", "second");
    git(&source, &["push", "private", "main"], true);
    git(&clone, &["fetch", "origin"], true);
    assert_eq!(
        git(&clone, &["rev-parse", "refs/remotes/origin/main"], false),
        second
    );

    let third = commit(&source, "pulled writer content\n", "third");
    git(&source, &["push", "private", "main"], true);
    git(&clone, &["pull", "--ff-only"], true);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), third);
    assert_eq!(
        fs::read_to_string(clone.join("note.md")).unwrap(),
        "pulled writer content\n"
    );

    commit(&clone, "local reader change\n", "reader change");
    let expected_error =
        "this device is read-only for origin; ask an administrator for the write role";
    for args in [
        vec!["push", "origin", "HEAD:refs/heads/main"],
        vec!["push", "--dry-run", "origin", "HEAD:refs/heads/main"],
        vec!["push", "--force", "origin", "HEAD:refs/heads/main"],
    ] {
        let before = snapshot_tree(remote_path);
        let output = git_output(&clone, &args, true);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "push unexpectedly succeeded: {stderr}"
        );
        assert!(
            stderr.contains(expected_error),
            "push error did not explain the read-only role: {stderr}"
        );
        assert_eq!(
            snapshot_tree(remote_path),
            before,
            "rejected push changed storage"
        );
    }
}

#[test]
fn read_only_devices_use_both_storage_backends_without_publishing() {
    let temporary = tempfile::tempdir().unwrap();
    let filesystem_remote = temporary.path().join("filesystem-remote");
    let filesystem_url = format!("e2ee::{}", filesystem_remote.display());
    exercise_read_only_helper(
        temporary.path(),
        FilesystemStorage::new(&filesystem_remote),
        &filesystem_remote,
        &filesystem_url,
    );

    let _cache_lock: MutexGuard<'static, ()> = CACHE_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache_dir = temporary.path().join("isolated-carrier-cache");
    // Keep the carrier cache and all test objects outside the real user cache.
    unsafe { env::set_var("GIT_REMOTE_E2EE_CACHE_DIR", &cache_dir) };

    let carrier = temporary.path().join("carrier.git");
    let initialize_output = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&carrier)
        .output()
        .unwrap();
    assert!(initialize_output.status.success());
    let carrier_url = format!("e2ee::git+{}", carrier.display());
    exercise_read_only_helper(
        &temporary.path().join("carrier-case"),
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        &carrier,
        &carrier_url,
    );
}
