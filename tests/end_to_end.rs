use std::fs;
use std::path::Path;
use std::process::Command;

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::FilesystemStorage;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn initialize_git(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["config", "user.name", "E2EE Git Test"]);
    git(
        repo,
        &["config", "user.email", "git-remote-e2ee@example.invalid"],
    );
}

fn commit(repo: &Path, contents: &str, message: &str) -> String {
    fs::write(repo.join("note.md"), contents).unwrap();
    git(repo, &["add", "note.md"]);
    git(repo, &["commit", "-q", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
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
fn pushes_incrementally_and_fetches_into_another_repository() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key.clone());
    encrypted.initialize().unwrap();

    let first = commit(&source, "first\n", "first");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let first_state = encrypted.verify().unwrap();
    assert_eq!(first_state.generation, 1);
    assert_eq!(first_state.packs.len(), 1);

    let second = commit(&source, "second\n", "second");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let second_state = encrypted.verify().unwrap();
    assert_eq!(second_state.generation, 2);
    assert_eq!(second_state.packs.len(), 2);
    assert_eq!(second_state.refs["refs/heads/main"], second);

    encrypted.fetch_into(&destination, "encrypted").unwrap();
    assert_eq!(
        git(&destination, &["rev-parse", "refs/remotes/encrypted/main"]),
        second
    );
    assert_eq!(
        git(&destination, &["show", &format!("{first}:note.md")]),
        "first"
    );
    assert_eq!(
        git(&destination, &["show", &format!("{second}:note.md")]),
        "second"
    );
}

#[test]
fn rejects_non_fast_forward_update() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    let first = commit(&source, "first\n", "first");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    commit(&source, "second\n", "second");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    git(&source, &["reset", "--hard", &first]);
    commit(&source, "diverged\n", "diverged");

    let error = encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap_err();
    assert!(error.to_string().contains("non-fast-forward"));
    assert_eq!(encrypted.verify().unwrap().generation, 2);
}

#[test]
fn explicit_force_can_publish_a_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    let first = commit(&source, "first\n", "first");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    commit(&source, "second\n", "second");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();

    git(&source, &["reset", "--hard", &first]);
    encrypted
        .push_ref(&source, "refs/heads/main", true)
        .unwrap();
    assert_eq!(encrypted.verify().unwrap().refs["refs/heads/main"], first);

    encrypted.fetch_into(&destination, "encrypted").unwrap();
    assert_eq!(
        git(&destination, &["rev-parse", "refs/remotes/encrypted/main"]),
        first
    );
}

#[test]
fn detects_tampered_pack_ciphertext() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    commit(&source, "secret\n", "secret");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let manifest = encrypted.verify().unwrap();
    let id = &manifest.packs[0].id;
    let path = remote_path.join("objects").join(&id[..2]).join(id);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();

    assert!(encrypted.verify().is_err());
}

#[test]
fn rejects_storage_head_rollback_after_fetch_pins_history() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    commit(&source, "first\n", "first");
    let first_head = encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    commit(&source, "second\n", "second");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    encrypted.fetch_into(&destination, "encrypted").unwrap();

    fs::write(remote_path.join("HEAD"), format!("{first_head}\n")).unwrap();
    let error = encrypted.fetch_into(&destination, "encrypted").unwrap_err();
    assert!(error.to_string().contains("rolled back"));
}

#[test]
fn rejects_same_generation_manifest_fork_after_fetch_pins_history() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let fork_path = temporary.path().join("fork");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key.clone());
    encrypted.initialize().unwrap();
    commit(&source, "first\n", "first");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    encrypted.fetch_into(&destination, "encrypted").unwrap();

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

    let error = encrypted.fetch_into(&destination, "encrypted").unwrap_err();
    assert!(error.to_string().contains("history forked"));
}

#[test]
fn writer_can_add_branch_without_having_other_remote_branch_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let first_writer = temporary.path().join("first-writer");
    let second_writer = temporary.path().join("second-writer");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&first_writer);
    initialize_git(&second_writer);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    let main = commit(&first_writer, "main\n", "main");
    encrypted
        .push_ref(&first_writer, "refs/heads/main", false)
        .unwrap();

    git(&second_writer, &["switch", "-c", "other"]);
    let other = commit(&second_writer, "other\n", "other");
    encrypted
        .push_ref(&second_writer, "refs/heads/other", false)
        .unwrap();

    encrypted.fetch_into(&destination, "encrypted").unwrap();
    assert_eq!(
        git(&destination, &["rev-parse", "refs/remotes/encrypted/main"]),
        main
    );
    assert_eq!(
        git(&destination, &["rev-parse", "refs/remotes/encrypted/other"]),
        other
    );
}

#[test]
fn rejects_tag_destinations_consistently() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    commit(&source, "tagged\n", "tagged");
    git(&source, &["tag", "v1"]);

    let error = encrypted
        .push_update(&source, "refs/tags/v1", "refs/tags/v1", false)
        .unwrap_err();
    assert!(error.to_string().contains("only refs/heads"));
    assert_eq!(encrypted.verify().unwrap().generation, 0);
}
