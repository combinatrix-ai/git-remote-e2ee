use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use anyhow::Result;
use base64::Engine;
use git_remote_e2ee::crypto::{KeyFile, object_id, random_key};
use git_remote_e2ee::manifest::{
    Manifest, ManifestAuthorization, open_manifest, peek_manifest_header, seal_manifest,
    unwrap_generation_key, verify_manifest, wrap_predecessor_key,
};
use git_remote_e2ee::policy::{DeviceRoles, PolicyState};
use git_remote_e2ee::repository::{EncryptedRepository, RecoveryClass, RecoveryOptions};
use git_remote_e2ee::storage::{
    FilesystemStorage, ObjectKind, ObjectStage, RecoveryCommit, RecoveryHistory, Storage,
};

#[derive(Clone)]
struct BarrierStorage {
    inner: FilesystemStorage,
    armed: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
    barrier: Arc<Barrier>,
}

#[derive(Clone)]
struct OverBudgetHistoryStorage {
    inner: FilesystemStorage,
}

impl Storage for OverBudgetHistoryStorage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        self.inner.begin_object(kind)
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        self.inner.open_object(kind, id)
    }

    fn read_head(&self) -> Result<Option<String>> {
        self.inner.read_head()
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        self.inner.compare_and_swap_head(expected, next)
    }

    fn recovery_history(
        &self,
        max_commits: usize,
        _max_manifest_bytes: u64,
    ) -> Result<Option<RecoveryHistory>> {
        Ok(Some(RecoveryHistory {
            commits: (0..=max_commits)
                .map(|index| RecoveryCommit {
                    commit_id: format!("commit-{index}"),
                    head_id: self.inner.read_head().unwrap(),
                })
                .collect(),
            manifests: Default::default(),
        }))
    }
}

impl Storage for BarrierStorage {
    fn begin_object(&self, kind: ObjectKind) -> Result<Box<dyn ObjectStage>> {
        self.inner.begin_object(kind)
    }

    fn open_object(&self, kind: ObjectKind, id: &str) -> Result<Box<dyn Read + Send>> {
        self.inner.open_object(kind, id)
    }

    fn read_head(&self) -> Result<Option<String>> {
        let head = self.inner.read_head()?;
        if self.armed.load(Ordering::SeqCst) && self.reads.fetch_add(1, Ordering::SeqCst) < 2 {
            self.barrier.wait();
        }
        Ok(head)
    }

    fn compare_and_swap_head(&self, expected: Option<&str>, next: &str) -> Result<()> {
        self.inner.compare_and_swap_head(expected, next)
    }
}

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

fn client_state(repo: &Path, remote_name: &str) -> serde_json::Value {
    let path = repo
        .join(".git/git-remote-e2ee")
        .join(remote_name)
        .join("state.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
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
fn missing_pack_observation_does_not_advance_the_floor() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    repository.initialize().unwrap();
    commit(&source, "first\n", "first");
    repository
        .push_update_for_remote(
            &source,
            "encrypted",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();
    repository.fetch_into(&destination, "encrypted").unwrap();
    assert_eq!(client_state(&destination, "encrypted")["generation"], 1);
    assert_eq!(
        client_state(&destination, "encrypted")["imported_generation"],
        1
    );

    commit(&source, "second\n", "second");
    repository
        .push_update_for_remote(
            &source,
            "encrypted",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();
    let (_, manifest) = repository.current_manifest().unwrap();
    let pack_id = manifest.new_packs[0].id.clone();
    let pack_path = remote_path
        .join("objects")
        .join(&pack_id[..2])
        .join(&pack_id);
    let saved_pack = fs::read(&pack_path).unwrap();
    fs::remove_file(&pack_path).unwrap();

    let listed = repository
        .observe_manifest(&destination, "encrypted")
        .unwrap();
    assert_eq!(listed.generation, 2);
    assert_eq!(client_state(&destination, "encrypted")["generation"], 1);
    let error = repository
        .fetch_into(&destination, "encrypted")
        .unwrap_err()
        .to_string();
    assert!(error.contains(&pack_id), "unexpected error: {error}");
    assert_eq!(client_state(&destination, "encrypted")["generation"], 1);

    write_stored_object(&remote_path, "objects", &pack_id, &saved_pack);
    let fetched = repository.fetch_into(&destination, "encrypted").unwrap();
    assert_eq!(fetched.generation, 2);
    let state = client_state(&destination, "encrypted");
    assert_eq!(state["generation"], 2);
    assert_eq!(state["imported_generation"], 2);
}

#[test]
fn successful_own_publication_advances_the_client_floor() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    repository.initialize().unwrap();
    commit(&source, "published\n", "published");
    let head = repository
        .push_update_for_remote(
            &source,
            "encrypted",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();

    let state_path = source.join(".git/git-remote-e2ee/encrypted/state.json");
    let state: serde_json::Value = serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
    assert_eq!(state["head_id"], head);
    assert_eq!(state["generation"], 1);
    assert_eq!(state["imported_generation"], serde_json::Value::Null);
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
    let (policy, _) = PolicyState::genesis(&key).unwrap();
    policy.validate_genesis(&key.repository_root).unwrap();
    let current_key = unwrap_generation_key(&header, &key).unwrap();
    let current = open_manifest(&manifest_bytes, &current_key).unwrap();
    verify_manifest(&current, &policy, None, &current_key).unwrap();
    let current = current.manifest().clone();

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
        introduced_policy: None,
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
    assert_eq!(client_state(&destination, "e2ee")["generation"], 1);
    assert_eq!(client_state(&destination, "e2ee")["imported_generation"], 1);
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

#[test]
fn local_publication_advances_verified_frontier_before_observation() {
    const CHILD_ENV: &str = "E2EE_TEST_FRONTIER_TRACE_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_publication_advances_verified_frontier_before_observation",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env("GIT_REMOTE_E2EE_TRACE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "frontier trace child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let trace = String::from_utf8_lossy(&output.stderr);
        let counters: Vec<_> = trace
            .lines()
            .filter(|line| line.contains("count=git_ref_connectivity_walk_objects"))
            .collect();
        assert_eq!(counters.len(), 1, "expected one connectivity walk: {trace}");
        assert!(
            counters[0].ends_with("value=0"),
            "the observation re-walked published history: {}",
            counters[0]
        );
        return;
    }

    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key);
    repository.initialize().unwrap();

    let first = commit(&source, "first\n", "first");
    repository
        .push_update_for_remote(
            &source,
            "origin",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();
    assert_eq!(
        client_state(&source, "origin")["verified_refs"]["refs/heads/main"],
        first
    );

    let observed = repository.observe_manifest(&source, "origin").unwrap();
    assert_eq!(observed.refs.get("refs/heads/main"), Some(&first));

    let second = commit(&source, "second\n", "second");
    repository
        .push_update_for_remote(
            &source,
            "origin",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();
    assert_eq!(
        client_state(&source, "origin")["verified_refs"]["refs/heads/main"],
        second
    );
}

#[test]
fn shallow_publication_does_not_advance_verified_frontier() {
    let temporary = tempfile::tempdir().unwrap();
    let full_source = temporary.path().join("full-source");
    let shallow_source = temporary.path().join("shallow-source");
    let remote = temporary.path().join("remote");
    initialize_git(&full_source);
    commit(&full_source, "first\n", "first");
    commit(&full_source, "second\n", "second");

    let source_url = format!("file://{}", full_source.display());
    let clone = Command::new("git")
        .args(["clone", "--quiet", "--depth=1", "--no-tags"])
        .arg(&source_url)
        .arg(&shallow_source)
        .output()
        .unwrap();
    assert!(
        clone.status.success(),
        "git clone: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert_eq!(
        git(&shallow_source, &["rev-parse", "--is-shallow-repository"]),
        "true"
    );

    let key = KeyFile::generate();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key);
    repository.initialize().unwrap();
    repository
        .push_update_for_remote(
            &shallow_source,
            "origin",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();

    assert!(
        client_state(&shallow_source, "origin")["verified_refs"]
            .as_object()
            .unwrap()
            .is_empty()
    );
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
    copy_tree(&fork_path.join("manifests"), &remote_path.join("manifests"));
    fs::write(remote_path.join("HEAD"), format!("{fork_head}\n")).unwrap();

    let error = encrypted.fetch_into(&destination, "encrypted").unwrap_err();
    assert!(error.to_string().contains("history forked"));
}

#[test]
fn recover_replaces_reader_signed_junk_from_the_directory_floor() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    let fresh = temporary.path().join("fresh");
    let storage_path = temporary.path().join("storage");
    initialize_git(&source);
    initialize_git(&returning);
    initialize_git(&fresh);

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let storage = FilesystemStorage::new(&storage_path);
    let repository = EncryptedRepository::new(storage.clone(), owner.clone());
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    commit(&source, "recovery keeps this content\n", "base");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    repository.fetch_into(&returning, "encrypted").unwrap();
    let (floor_id, floor_manifest) = repository.current_manifest().unwrap();
    let floor_generation = floor_manifest.generation;
    let floor_state = client_state(&returning, "encrypted");
    assert_eq!(floor_state["head_id"], floor_id);

    let encrypted = storage.get_object(ObjectKind::Manifest, &floor_id).unwrap();
    let header = peek_manifest_header(&encrypted).unwrap();
    let floor_key = unwrap_generation_key(&header, &reader).unwrap();
    let opened = open_manifest(&encrypted, &floor_key).unwrap();
    let policy =
        PolicyState::parse(opened.manifest().introduced_policy.as_deref().unwrap()).unwrap();
    let recovery_key = random_key();
    let junk = Manifest {
        format_version: floor_manifest.format_version,
        repository_root: floor_manifest.repository_root.clone(),
        generation: floor_generation + 1,
        previous: Some(floor_id.clone()),
        policy_id: floor_manifest.policy_id.clone(),
        policy_generation: floor_manifest.policy_generation,
        authorization: ManifestAuthorization::Writer,
        total_pack_count: floor_manifest.total_pack_count,
        refs: floor_manifest.refs.clone(),
        new_packs: Vec::new(),
        predecessor_key_wrap: Some(
            wrap_predecessor_key(
                &recovery_key,
                &floor_key,
                &floor_manifest.repository_root,
                floor_generation + 1,
                &floor_id,
            )
            .unwrap(),
        ),
        introduced_policy: None,
    };
    let junk_bytes = seal_manifest(
        &reader,
        &policy,
        &recovery_key,
        ManifestAuthorization::Writer,
        junk,
    )
    .unwrap();
    let junk_id = object_id(&junk_bytes);
    storage
        .put_object_if_absent(ObjectKind::Manifest, &junk_id, &junk_bytes)
        .unwrap();
    storage
        .compare_and_swap_head(Some(&floor_id), &junk_id)
        .unwrap();

    let recoverer = EncryptedRepository::new(storage.clone(), owner.clone());
    let blocked = recoverer
        .recover(
            &returning,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(blocked.classification, RecoveryClass::Invalid);
    assert_eq!(blocked.default_base.as_deref(), Some(floor_id.as_str()));
    assert!(
        blocked
            .warning
            .as_deref()
            .unwrap()
            .starts_with("Updates after this floor")
    );
    assert!(
        blocked
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("--accept-stale-floor")
    );
    assert_eq!(client_state(&returning, "encrypted")["head_id"], floor_id);

    let recovered = recoverer
        .recover(
            &returning,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: true,
            },
        )
        .unwrap();
    let recovered_id = recovered.published_manifest.unwrap();
    let (current_id, current) = recoverer.current_manifest().unwrap();
    assert_eq!(current_id, recovered_id);
    assert_eq!(current.previous.as_deref(), Some(floor_id.as_str()));
    assert_eq!(current.generation, floor_generation + 1);
    assert_ne!(current_id, junk_id);
    assert_eq!(client_state(&returning, "encrypted")["head_id"], current_id);
    let rejected =
        fs::read(returning.join(".git/git-remote-e2ee/encrypted/rejected-heads.json")).unwrap();
    assert!(String::from_utf8_lossy(&rejected).contains(&junk_id));

    recoverer.fetch_into(&returning, "encrypted").unwrap();
    recoverer.fetch_into(&fresh, "encrypted").unwrap();
    assert_eq!(
        git(&fresh, &["show", "refs/remotes/encrypted/main:note.md"]),
        "recovery keeps this content"
    );
    assert_eq!(client_state(&returning, "encrypted")["head_id"], current_id);
    assert_eq!(client_state(&fresh, "encrypted")["head_id"], current_id);
}

#[test]
fn recover_refuses_a_revoked_devices_unverifiable_head() {
    let temporary = tempfile::tempdir().unwrap();
    let reader_repo = temporary.path().join("reader");
    let storage_path = temporary.path().join("storage");
    initialize_git(&reader_repo);
    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let storage = FilesystemStorage::new(&storage_path);
    let owner_repository = EncryptedRepository::new(storage.clone(), owner);
    owner_repository.initialize().unwrap();
    owner_repository.pin_admin_state(&admin_pin).unwrap();
    owner_repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    owner_repository
        .fetch_into(&reader_repo, "encrypted")
        .unwrap();
    let old_floor = client_state(&reader_repo, "encrypted")["head_id"]
        .as_str()
        .unwrap()
        .to_owned();
    owner_repository
        .revoke_device(&reader.device_id().unwrap(), &admin_pin)
        .unwrap();
    let revoked_head = storage.read_head().unwrap().unwrap();

    let reader_repository = EncryptedRepository::new(storage.clone(), reader);
    let report = reader_repository
        .recover(
            &reader_repo,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: true,
            },
        )
        .unwrap();
    assert_eq!(report.classification, RecoveryClass::Unverifiable);
    assert!(report.blocked_reason.unwrap().contains("forbidden"));
    assert_eq!(
        storage.read_head().unwrap().as_deref(),
        Some(revoked_head.as_str())
    );
    assert_eq!(
        client_state(&reader_repo, "encrypted")["head_id"],
        old_floor
    );
    assert!(
        !reader_repo
            .join(".git/git-remote-e2ee/encrypted/rejected-heads.json")
            .exists()
    );
}

#[test]
fn recover_refuses_unknown_formats_and_missing_floor_objects() {
    let temporary = tempfile::tempdir().unwrap();

    let unknown_repo = temporary.path().join("unknown-repo");
    let unknown_storage_path = temporary.path().join("unknown-storage");
    initialize_git(&unknown_repo);
    let key = KeyFile::generate();
    let unknown_storage = FilesystemStorage::new(&unknown_storage_path);
    let unknown_repository = EncryptedRepository::new(unknown_storage.clone(), key.clone());
    unknown_repository.initialize().unwrap();
    unknown_repository
        .fetch_into(&unknown_repo, "encrypted")
        .unwrap();
    let floor_id = unknown_storage.read_head().unwrap().unwrap();
    let header = serde_json::json!({
        "format_version": 99,
        "repository_root": key.repository_root,
        "generation": 1,
        "previous": floor_id,
        "key_commitment": "0".repeat(64),
        "generation_key_envelopes": [],
        "body_digest": "0".repeat(64),
        "sealed_header_digest": "0".repeat(64)
    });
    let header_bytes = serde_json::to_vec(&header).unwrap();
    let unsupported_bytes = serde_json::to_vec(&serde_json::json!({
        "header": base64::engine::general_purpose::STANDARD.encode(header_bytes),
        "sealed_header_ciphertext": "",
        "body_ciphertext": ""
    }))
    .unwrap();
    let unsupported_id = object_id(&unsupported_bytes);
    unknown_storage
        .put_object_if_absent(ObjectKind::Manifest, &unsupported_id, &unsupported_bytes)
        .unwrap();
    unknown_storage
        .compare_and_swap_head(Some(&floor_id), &unsupported_id)
        .unwrap();
    let unsupported = EncryptedRepository::new(unknown_storage.clone(), key)
        .recover(
            &unknown_repo,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: true,
            },
        )
        .unwrap();
    assert_eq!(unsupported.classification, RecoveryClass::Unsupported);
    assert_eq!(
        unknown_storage.read_head().unwrap().as_deref(),
        Some(unsupported_id.as_str())
    );

    let missing_repo = temporary.path().join("missing-repo");
    let missing_storage_path = temporary.path().join("missing-storage");
    initialize_git(&missing_repo);
    let missing_key = KeyFile::generate();
    let missing_storage = FilesystemStorage::new(&missing_storage_path);
    let missing_repository = EncryptedRepository::new(missing_storage.clone(), missing_key.clone());
    missing_repository.initialize().unwrap();
    let source = temporary.path().join("missing-source");
    initialize_git(&source);
    commit(&source, "required floor object\n", "required");
    missing_repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    missing_repository
        .fetch_into(&missing_repo, "encrypted")
        .unwrap();
    let floor_id = missing_storage.read_head().unwrap().unwrap();
    let floor_manifest = missing_repository.current_manifest().unwrap().1;
    let missing_pack = &floor_manifest.new_packs[0].id;
    fs::remove_file(
        missing_storage_path
            .join("objects")
            .join(&missing_pack[..2])
            .join(missing_pack),
    )
    .unwrap();
    let unavailable = missing_repository
        .recover(
            &missing_repo,
            "encrypted",
            RecoveryOptions {
                publish: false,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(unavailable.classification, RecoveryClass::Unavailable);
    let invalid_bytes = b"invalid successor";
    let invalid_id = object_id(invalid_bytes);
    missing_storage
        .put_object_if_absent(ObjectKind::Manifest, &invalid_id, invalid_bytes)
        .unwrap();
    missing_storage
        .compare_and_swap_head(Some(&floor_id), &invalid_id)
        .unwrap();
    let refused = EncryptedRepository::new(missing_storage.clone(), missing_key)
        .recover(
            &missing_repo,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: true,
            },
        )
        .unwrap();
    assert_eq!(refused.classification, RecoveryClass::Invalid);
    assert!(
        refused
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("ciphertext is unavailable")
    );
    assert_eq!(
        missing_storage.read_head().unwrap().as_deref(),
        Some(invalid_id.as_str())
    );
    assert_eq!(
        client_state(&missing_repo, "encrypted")["head_id"],
        floor_id
    );
}

#[test]
fn recover_never_overrides_authenticated_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    let storage_path = temporary.path().join("storage");
    initialize_git(&source);
    initialize_git(&returning);
    let key = KeyFile::generate();
    let storage = FilesystemStorage::new(&storage_path);
    let repository = EncryptedRepository::new(storage.clone(), key);
    repository.initialize().unwrap();
    commit(&source, "one\n", "one");
    let first = repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    commit(&source, "two\n", "two");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&returning, "encrypted").unwrap();
    storage
        .compare_and_swap_head(Some(&repository.current_manifest().unwrap().0), &first)
        .unwrap();

    let report = repository
        .recover(
            &returning,
            "encrypted",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: true,
                accept_stale_floor: true,
            },
        )
        .unwrap();
    assert_eq!(report.classification, RecoveryClass::Discontinuous);
    assert!(report.blocked_reason.unwrap().contains("forbidden"));
    assert_eq!(
        storage.read_head().unwrap().as_deref(),
        Some(first.as_str())
    );
}

#[test]
fn recovery_discovery_budget_exhaustion_fails_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let repo = temporary.path().join("repo");
    let storage_path = temporary.path().join("storage");
    initialize_git(&repo);
    let key = KeyFile::generate();
    let inner = FilesystemStorage::new(&storage_path);
    let repository = EncryptedRepository::new(inner.clone(), key.clone());
    repository.initialize().unwrap();
    repository.fetch_into(&repo, "encrypted").unwrap();
    let floor = inner.read_head().unwrap().unwrap();
    let invalid_bytes = b"malformed successor";
    let invalid_id = object_id(invalid_bytes);
    inner
        .put_object_if_absent(ObjectKind::Manifest, &invalid_id, invalid_bytes)
        .unwrap();
    inner
        .compare_and_swap_head(Some(&floor), &invalid_id)
        .unwrap();

    let recovery = EncryptedRepository::new(
        OverBudgetHistoryStorage {
            inner: inner.clone(),
        },
        key,
    );
    let error = recovery
        .recover(
            &repo,
            "encrypted",
            RecoveryOptions {
                publish: false,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("outer-commit budget exhausted"));
    assert_eq!(
        inner.read_head().unwrap().as_deref(),
        Some(invalid_id.as_str())
    );
    assert_eq!(client_state(&repo, "encrypted")["head_id"], floor);
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
fn deletion_and_tag_publication_race_with_exactly_one_cas_winner() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote = temporary.path().join("remote");
    initialize_git(&source);
    let key = KeyFile::generate();
    let seed_repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key.clone());
    seed_repository.initialize().unwrap();
    let main = commit(&source, "main\n", "main");
    seed_repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    git(&source, &["branch", "doomed", &main]);
    seed_repository
        .push_ref(&source, "refs/heads/doomed", false)
        .unwrap();
    git(&source, &["tag", "race-tag", &main]);
    let before = seed_repository.verify().unwrap();

    let storage = BarrierStorage {
        inner: FilesystemStorage::new(&remote),
        armed: Arc::new(AtomicBool::new(true)),
        reads: Arc::new(AtomicUsize::new(0)),
        barrier: Arc::new(Barrier::new(2)),
    };
    let deleter = EncryptedRepository::new(storage.clone(), key.clone());
    let tagger = EncryptedRepository::new(storage, key);
    let deletion_repo = source.clone();
    let tag_repo = source.clone();
    let deletion = thread::spawn(move || deleter.delete_ref(&deletion_repo, "refs/heads/doomed"));
    let tag_push = thread::spawn(move || {
        tagger.push_update(&tag_repo, "refs/tags/race-tag", "refs/tags/race-tag", false)
    });
    let deletion = deletion.join().unwrap();
    let tag_push = tag_push.join().unwrap();
    assert_ne!(deletion.is_ok(), tag_push.is_ok());
    let loser = if deletion.is_err() {
        deletion
    } else {
        tag_push
    };
    assert!(
        loser
            .unwrap_err()
            .to_string()
            .contains("head changed concurrently")
    );

    let after = seed_repository.verify().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    let deletion_won = !after.refs.contains_key("refs/heads/doomed");
    let tag_push_won = after.refs.contains_key("refs/tags/race-tag");
    assert_ne!(deletion_won, tag_push_won);
    assert_eq!(
        after.total_pack_count,
        before.total_pack_count + u64::from(tag_push_won)
    );
}

#[test]
fn rejects_unsupported_ref_namespaces_consistently() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    initialize_git(&source);

    let key = KeyFile::generate();
    let encrypted = EncryptedRepository::new(FilesystemStorage::new(&remote_path), key);
    encrypted.initialize().unwrap();
    commit(&source, "tagged\n", "tagged");
    let error = encrypted
        .push_update(&source, "refs/heads/main", "refs/notes/review", false)
        .unwrap_err();
    assert!(error.to_string().contains("unsupported ref namespace"));
    assert_eq!(encrypted.verify().unwrap().generation, 0);
}

fn git_e2ee(workdir: &Path, args: &[impl AsRef<std::ffi::OsStr>]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_git-e2ee"))
        .current_dir(workdir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git-e2ee {:?} status {:?}\nstdout {}\nstderr {}",
        args.iter().map(|arg| arg.as_ref()).collect::<Vec<_>>(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn init_with_relative_storage_creates_the_store_in_the_child_cwd() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    fs::create_dir(&work).unwrap();
    let key_path = root.path().join("fixture.key.json");
    KeyFile::generate().write_new(&key_path).unwrap();
    git_e2ee(
        &work,
        &[
            "init",
            "--storage",
            "relative-store",
            "--key",
            key_path.to_str().unwrap(),
        ],
    );
    assert!(work.join("relative-store/objects").is_dir());
    assert!(work.join("relative-store/manifests").is_dir());
    assert!(!work.join("relative-store/policies").exists());
    assert!(!root.path().join("relative-store").exists());
}

#[test]
fn relative_dotdot_storage_follows_the_filesystem() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let nested = work.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let key_path = root.path().join("fixture.key.json");
    KeyFile::generate().write_new(&key_path).unwrap();
    git_e2ee(
        &nested,
        &[
            "init",
            "--storage",
            "../sibling-store",
            "--key",
            key_path.to_str().unwrap(),
        ],
    );
    assert!(work.join("sibling-store/objects").is_dir());
    assert!(!nested.join("sibling-store").exists());

    #[cfg(unix)]
    {
        let holder = tempfile::tempdir().unwrap();
        let outside_parent = holder.path().join("outside-parent");
        let outside = outside_parent.join("target");
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, work.join("link")).unwrap();
        let key_path = root.path().join("fixture-dotdot.key.json");
        KeyFile::generate().write_new(&key_path).unwrap();
        git_e2ee(
            &work,
            &[
                "init",
                "--storage",
                "link/../dotdot-store",
                "--key",
                key_path.to_str().unwrap(),
            ],
        );
        assert!(outside_parent.join("dotdot-store/objects").is_dir());
        assert!(!work.join("dotdot-store").exists());
    }
}
