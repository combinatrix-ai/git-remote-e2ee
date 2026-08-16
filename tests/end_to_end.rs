use std::fs;
use std::path::Path;
use std::process::Command;

use git_remote_e2ee::crypto::{KeyFile, object_id, random_key};
use git_remote_e2ee::manifest::{
    Manifest, ManifestAuthorization, open_manifest, peek_manifest_header, seal_manifest,
    unwrap_generation_key, wrap_predecessor_key,
};
use git_remote_e2ee::policy::PolicyState;
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
    assert_eq!(first_state.total_pack_count, 1);

    let second = commit(&source, "second\n", "second");
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let second_state = encrypted.verify().unwrap();
    assert_eq!(second_state.generation, 2);
    assert_eq!(second_state.total_pack_count, 2);
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
fn returning_client_fetches_multiple_offline_generations_from_deltas() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);
    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key);
    repository.initialize().unwrap();

    commit(&source, "one\n", "one");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&destination, "e2ee").unwrap();

    for value in ["two\n", "three\n", "four\n"] {
        commit(&source, value, value.trim());
        repository
            .push_ref(&source, "refs/heads/main", false)
            .unwrap();
    }
    let latest = repository.fetch_into(&destination, "e2ee").unwrap();
    assert_eq!(latest.total_pack_count, 4);
    assert_eq!(
        git(&destination, &["show", "refs/remotes/e2ee/main:note.md"]),
        "four"
    );
}

#[test]
fn returning_client_rejects_signed_ref_advance_without_its_pack() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);
    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key.clone());
    repository.initialize().unwrap();
    commit(&source, "valid\n", "valid");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&destination, "e2ee").unwrap();

    let head = fs::read_to_string(remote.join("HEAD"))
        .unwrap()
        .trim()
        .to_owned();
    let manifest_bytes = read_stored_object(&remote, "manifests", &head);
    let header = peek_manifest_header(&manifest_bytes).unwrap();
    let policy_bytes = read_stored_object(&remote, "policies", &header.policy_id);
    let policy = PolicyState::parse(&policy_bytes).unwrap();
    policy.validate_genesis(&key.repository_root).unwrap();
    let current_key = unwrap_generation_key(&header, &key).unwrap();
    let current = open_manifest(&manifest_bytes, &policy, None, &current_key).unwrap();

    let next_key = random_key();
    let generation = current.generation + 1;
    let mut refs = current.refs.clone();
    refs.insert("refs/heads/main".to_owned(), "1".repeat(40));
    let malicious = Manifest {
        format_version: current.format_version,
        repository_root: current.repository_root.clone(),
        generation,
        previous: Some(head.clone()),
        policy_id: policy.id.clone(),
        policy_generation: policy.body.generation,
        authorization: ManifestAuthorization::Writer,
        total_pack_count: current.total_pack_count,
        refs,
        new_packs: Vec::new(),
        predecessor_key_wrap: Some(
            wrap_predecessor_key(
                &next_key,
                &current_key,
                &current.repository_root,
                generation,
                &head,
            )
            .unwrap(),
        ),
    };
    let malicious_bytes = seal_manifest(
        &key,
        &policy,
        &next_key,
        ManifestAuthorization::Writer,
        malicious,
    )
    .unwrap();
    let malicious_id = object_id(&malicious_bytes);
    write_stored_object(&remote, "manifests", &malicious_id, &malicious_bytes);
    fs::write(remote.join("HEAD"), format!("{malicious_id}\n")).unwrap();

    let error = repository
        .fetch_into(&destination, "e2ee")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("does not resolve") || error.contains("missing Git objects"),
        "unexpected connectivity error: {error}"
    );
}

#[test]
fn missing_verified_frontier_tip_fails_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key);
    repository.initialize().unwrap();
    commit(&source, "valid\n", "valid");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&destination, "e2ee").unwrap();

    let state_path = destination.join(".git/git-remote-e2ee/e2ee/state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    state["verified_refs"]["refs/heads/main"] = serde_json::Value::String("1".repeat(40));
    fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let error = repository
        .fetch_into(&destination, "e2ee")
        .unwrap_err()
        .to_string();
    assert!(error.contains("verified ref refs/heads/main is missing locally"));
}

fn read_stored_object(root: &Path, kind: &str, id: &str) -> Vec<u8> {
    fs::read(root.join(kind).join(&id[..2]).join(id)).unwrap()
}

fn write_stored_object(root: &Path, kind: &str, id: &str, bytes: &[u8]) {
    let directory = root.join(kind).join(&id[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(id), bytes).unwrap();
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
    let id = &manifest.new_packs[0].id;
    let path = remote_path.join("objects").join(&id[..2]).join(id);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();

    assert!(encrypted.verify().is_err());
}

#[test]
fn late_stream_authentication_failure_does_not_advance_refs_or_pins() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let mut state = 0x9e37_79b9_u32;
    let contents: Vec<u8> = (0..(2 * 1024 * 1024 + 123))
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    fs::write(source.join("large.bin"), contents).unwrap();
    git(&source, &["add", "large.bin"]);
    git(&source, &["commit", "-q", "-m", "large"]);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    encrypted
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let manifest = encrypted.current_manifest().unwrap().1;
    let id = &manifest.new_packs[0].id;
    let path = remote_path.join("objects").join(&id[..2]).join(id);
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 1024 * 1024 * 2);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(path, bytes).unwrap();

    assert!(encrypted.fetch_into(&destination, "encrypted").is_err());
    assert!(
        !destination
            .join(".git/git-remote-e2ee/encrypted/state.json")
            .exists()
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&destination)
        .args(["rev-parse", "--verify", "refs/remotes/encrypted/main"])
        .output()
        .unwrap();
    assert!(!output.status.success());
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
    let remote_path = temporary.path().join("remote");
    initialize_git(&first_writer);
    initialize_git(&second_writer);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    let main = commit(&first_writer, "main\n", "main");
    encrypted
        .push_ref(&first_writer, "refs/heads/main", false)
        .unwrap();
    encrypted.fetch_into(&second_writer, "encrypted").unwrap();
    git(
        &second_writer,
        &["switch", "-q", "-c", "other", "refs/remotes/encrypted/main"],
    );

    git(&first_writer, &["switch", "-q", "-c", "feature"]);
    let feature = commit(&first_writer, "feature\n", "feature");
    encrypted
        .push_ref(&first_writer, "refs/heads/feature", false)
        .unwrap();

    let other = commit(&second_writer, "other\n", "other");
    encrypted
        .push_update_for_remote(
            &second_writer,
            "encrypted",
            "refs/heads/other",
            "refs/heads/other",
            false,
        )
        .unwrap();

    encrypted.fetch_into(&second_writer, "encrypted").unwrap();
    assert_eq!(
        git(
            &second_writer,
            &["rev-parse", "refs/remotes/encrypted/main"]
        ),
        main
    );
    assert_eq!(
        git(
            &second_writer,
            &["rev-parse", "refs/remotes/encrypted/feature"]
        ),
        feature
    );
    assert_eq!(
        git(
            &second_writer,
            &["rev-parse", "refs/remotes/encrypted/other"]
        ),
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
