use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::FilesystemStorage;

fn git_output(repo: &Path, args: &[&str], with_helper: bool) -> Output {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo).args(args);
    if with_helper {
        let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
        let mut paths = vec![helper.parent().unwrap().to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        command.env("PATH", env::join_paths(paths).unwrap());
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

fn configure_remote(repo: &Path, remote_path: &Path, key_path: &Path) {
    let remote_url = format!("e2ee::{}", remote_path.display());
    let key_path = key_path.to_string_lossy();
    git(repo, &["remote", "add", "private", &remote_url], false);
    git(
        repo,
        &["config", "remote.private.e2ee-key", &key_path],
        false,
    );
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

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn native_git_push_and_fetch_use_the_remote_helper() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    EncryptedRepository::new(FilesystemStorage::new(&remote_path), key)
        .initialize()
        .unwrap();

    fs::write(source.join("note.md"), "through native Git\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    let source_head = git(&source, &["rev-parse", "HEAD"], false);

    let remote_url = format!("e2ee::{}", remote_path.display());
    let key_path = key_path.to_string_lossy();
    git(&source, &["remote", "add", "private", &remote_url], false);
    git(
        &source,
        &["config", "remote.private.e2ee-key", &key_path],
        false,
    );
    git(
        &source,
        &["push", "private", "refs/heads/main:refs/heads/main"],
        true,
    );

    git(
        &destination,
        &["remote", "add", "private", &remote_url],
        false,
    );
    git(
        &destination,
        &["config", "remote.private.e2ee-key", &key_path],
        false,
    );
    git(&destination, &["fetch", "private"], true);
    assert_eq!(
        git(
            &destination,
            &["rev-parse", "refs/remotes/private/main"],
            false,
        ),
        source_head
    );
    assert_eq!(
        git(
            &destination,
            &["show", "refs/remotes/private/main:note.md"],
            false,
        ),
        "through native Git"
    );
}

#[test]
fn native_git_dry_run_does_not_mutate_remote() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();

    fs::write(source.join("note.md"), "dry run only\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    let remote_url = format!("e2ee::{}", remote_path.display());
    let key_path = key_path.to_string_lossy();
    git(&source, &["remote", "add", "private", &remote_url], false);
    git(
        &source,
        &["config", "remote.private.e2ee-key", &key_path],
        false,
    );

    git(
        &source,
        &[
            "push",
            "--dry-run",
            "private",
            "refs/heads/main:refs/heads/main",
        ],
        true,
    );
    let manifest = encrypted.verify().unwrap();
    assert_eq!(manifest.generation, 0);
    assert!(manifest.refs.is_empty());
}

#[test]
fn native_git_fetch_rejects_rollback_even_when_objects_are_local() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    fs::write(source.join("note.md"), "first\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "first"], false);
    git(&source, &["push", "private", "main"], true);
    let first_remote_head = encrypted.current_manifest().unwrap().0;
    git(&destination, &["fetch", "private"], true);

    fs::write(source.join("note.md"), "second\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "second"], false);
    let second_commit = git(&source, &["rev-parse", "HEAD"], false);
    git(&source, &["push", "private", "main"], true);
    git(&destination, &["fetch", "private"], true);
    assert_eq!(
        git(
            &destination,
            &["rev-parse", "refs/remotes/private/main"],
            false,
        ),
        second_commit
    );

    fs::write(remote_path.join("HEAD"), format!("{first_remote_head}\n")).unwrap();
    let output = git_output(&destination, &["fetch", "private"], true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rolled back"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        git(
            &destination,
            &["rev-parse", "refs/remotes/private/main"],
            false,
        ),
        second_commit
    );
}

#[test]
fn native_git_push_rejects_storage_rollback_before_creating_a_fork() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    configure_remote(&source, &remote_path, &key_path);

    fs::write(source.join("note.md"), "first\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "first"], false);
    git(&source, &["push", "private", "main"], true);
    let first_remote_head = encrypted.current_manifest().unwrap().0;

    fs::write(source.join("note.md"), "second\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "second"], false);
    git(&source, &["push", "private", "main"], true);

    fs::write(remote_path.join("HEAD"), format!("{first_remote_head}\n")).unwrap();
    fs::write(source.join("note.md"), "third\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "third"], false);
    let output = git_output(&source, &["push", "private", "main"], true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rolled back"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(encrypted.current_manifest().unwrap().0, first_remote_head);
}

#[test]
fn native_git_fetch_rejects_same_generation_manifest_fork() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let fork_path = temporary.path().join("fork");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key.clone());
    encrypted.initialize().unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    fs::write(source.join("note.md"), "same object, different manifest\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    git(&source, &["push", "private", "main"], true);
    git(&destination, &["fetch", "private"], true);

    let fork = EncryptedRepository::new(FilesystemStorage::new(&fork_path), key);
    fork.initialize().unwrap();
    let fork_head = fork.push_ref(&source, "refs/heads/main", false).unwrap();
    let fork_manifest = fork_path
        .join("manifests")
        .join(&fork_head[..2])
        .join(&fork_head);
    let remote_manifest = remote_path
        .join("manifests")
        .join(&fork_head[..2])
        .join(&fork_head);
    fs::create_dir_all(remote_manifest.parent().unwrap()).unwrap();
    fs::copy(fork_manifest, remote_manifest).unwrap();
    copy_tree(&fork_path.join("policies"), &remote_path.join("policies"));
    fs::write(remote_path.join("HEAD"), format!("{fork_head}\n")).unwrap();

    let output = git_output(&destination, &["fetch", "private"], true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("history forked"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
