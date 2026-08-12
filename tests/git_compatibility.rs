//! Black-box compatibility scenarios adapted from the behavior inventory in
//! Git upstream's `t/t5801-remote-helpers.sh`. This is an independent Rust
//! implementation, not a copy of Git's GPL test code.

use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::FilesystemStorage;

fn add_helper_to_path(command: &mut Command) {
    let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
    let mut paths = vec![helper.parent().unwrap().to_path_buf()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    command.env("PATH", env::join_paths(paths).unwrap());
}

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

fn initialize_git(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q", "-b", "main"], false);
    git(repo, &["config", "user.name", "E2EE Git Test"], false);
    git(
        repo,
        &["config", "user.email", "git-remote-e2ee@example.invalid"],
        false,
    );
}

fn commit_file(repo: &Path, contents: &str, message: &str) -> String {
    fs::write(repo.join("note.md"), format!("{contents}\n")).unwrap();
    git(repo, &["add", "note.md"], false);
    git(repo, &["commit", "-q", "-m", message], false);
    git(repo, &["rev-parse", "HEAD"], false)
}

fn setup_remote(root: &Path) -> (std::path::PathBuf, std::path::PathBuf, KeyFile) {
    let storage = root.join("storage");
    let key_path = root.join("repository.key.json");
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    EncryptedRepository::new(FilesystemStorage::new(&storage), key.clone())
        .initialize()
        .unwrap();
    (storage, key_path, key)
}

fn configure_remote(repo: &Path, storage: &Path, key_path: &Path) {
    let url = format!("e2ee::{}", storage.display());
    git(repo, &["remote", "add", "private", &url], false);
    git(
        repo,
        &[
            "config",
            "remote.private.e2ee-key",
            key_path.to_str().unwrap(),
        ],
        false,
    );
}

fn clone_remote(destination: &Path, storage: &Path, key_path: &Path) {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            &format!("e2ee.key={}", key_path.display()),
            "clone",
            "-q",
            &format!("e2ee::{}", storage.display()),
        ])
        .arg(destination);
    add_helper_to_path(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "clone stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    git(
        destination,
        &["config", "user.name", "E2EE Git Test"],
        false,
    );
    git(
        destination,
        &["config", "user.email", "git-remote-e2ee@example.invalid"],
        false,
    );
}

#[test]
fn upstream_style_clone_pull_and_branch_fetches_work() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let clone = temporary.path().join("clone");
    initialize_git(&source);
    let (storage, key_path, _) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);

    let first = commit_file(&source, "one", "one");
    git(&source, &["push", "private", "main"], true);
    clone_remote(&clone, &storage, &key_path);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), first);

    let second = commit_file(&source, "two", "two");
    git(&source, &["push", "private", "main"], true);
    git(&clone, &["pull", "--ff-only"], true);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), second);

    git(&source, &["switch", "-q", "-c", "new"], false);
    let new = commit_file(&source, "new branch", "new branch");
    git(&source, &["push", "private", "new"], true);
    git(&clone, &["fetch", "origin", "new"], true);
    assert_eq!(git(&clone, &["rev-parse", "FETCH_HEAD"], false), new);

    git(&clone, &["fetch", "origin"], true);
    assert_eq!(
        git(&clone, &["rev-parse", "refs/remotes/origin/main"], false),
        second
    );
    assert_eq!(
        git(&clone, &["rev-parse", "refs/remotes/origin/new"], false),
        new
    );
    git(&clone, &["fetch", "origin", "HEAD"], true);
    assert_eq!(git(&clone, &["rev-parse", "FETCH_HEAD"], false), second);
}

#[test]
fn upstream_style_push_refspecs_and_force_work() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    initialize_git(&source);
    let (storage, key_path, key) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);
    commit_file(&source, "base", "base");

    git(&source, &["switch", "-q", "-c", "named"], false);
    let named = commit_file(&source, "named", "named");
    git(&source, &["push", "private", "named"], true);
    git(&source, &["push", "private", "named:renamed"], true);
    git(&source, &["push", "private", "HEAD:from-head"], true);

    let repository = EncryptedRepository::new(FilesystemStorage::new(&storage), key.clone());
    let manifest = repository.verify().unwrap();
    for reference in ["named", "renamed", "from-head"] {
        assert_eq!(manifest.refs[&format!("refs/heads/{reference}")], named);
    }

    git(&source, &["reset", "--hard", "-q", "HEAD^"], false);
    let rewritten = commit_file(&source, "rewritten", "replacement");
    let rejected = git_output(&source, &["push", "private", "named"], true);
    assert!(!rejected.status.success());
    assert_eq!(repository.verify().unwrap().refs["refs/heads/named"], named);

    git(&source, &["push", "--force", "private", "named"], true);
    assert_eq!(
        repository.verify().unwrap().refs["refs/heads/named"],
        rewritten
    );
}

#[test]
fn unsupported_upstream_operations_fail_without_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    initialize_git(&source);
    let (storage, key_path, key) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);
    let head = commit_file(&source, "main", "main");
    git(&source, &["push", "private", "main"], true);

    let repository = EncryptedRepository::new(FilesystemStorage::new(&storage), key);
    let generation = repository.verify().unwrap().generation;

    let delete = git_output(&source, &["push", "private", ":main"], true);
    assert!(!delete.status.success());
    let after_delete = repository.verify().unwrap();
    assert_eq!(after_delete.generation, generation);
    assert_eq!(after_delete.refs["refs/heads/main"], head);

    git(&source, &["tag", "v1"], false);
    let tag = git_output(&source, &["push", "private", "v1"], true);
    assert!(!tag.status.success());
    let after_tag = repository.verify().unwrap();
    assert_eq!(after_tag.generation, generation);
    assert!(!after_tag.refs.contains_key("refs/tags/v1"));
}
