use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier};
use std::thread;

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{CasConflict, GitStorage};

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

fn init_source(path: &Path, marker: &str) -> String {
    fs::create_dir_all(path).unwrap();
    git(path, &["init", "-q", "-b", "main"], false);
    git(path, &["config", "user.name", "E2EE Git Test"], false);
    git(
        path,
        &["config", "user.email", "git-remote-e2ee@example.invalid"],
        false,
    );
    fs::write(path.join("note.md"), format!("{marker}\n")).unwrap();
    git(path, &["add", "note.md"], false);
    git(path, &["commit", "-q", "-m", "initial"], false);
    git(path, &["rev-parse", "HEAD"], false)
}

fn init_carrier(root: &Path, carrier: &Path, key: &KeyFile) {
    git(
        root,
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        key.clone(),
    )
    .initialize()
    .unwrap();
}

fn add_helper_to_path(command: &mut Command) {
    let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
    let mut paths = vec![helper.parent().unwrap().to_path_buf()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    command.env("PATH", env::join_paths(paths).unwrap());
}

#[test]
fn carrier_git_supports_native_push_and_clone_without_plaintext() {
    let temporary = tempfile::tempdir().unwrap();
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let clone = temporary.path().join("clone");
    let key_path = temporary.path().join("repository.key.json");

    let source_head = init_source(&source, "carrier secret marker");

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    init_carrier(temporary.path(), &carrier, &key);

    let url = format!("e2ee::git+{}", carrier.display());
    git(&source, &["remote", "add", "private", &url], false);
    git(
        &source,
        &[
            "config",
            "remote.private.e2ee-key",
            key_path.to_str().unwrap(),
        ],
        false,
    );
    git(&source, &["push", "private", "main"], true);

    let mut clone_command = Command::new("git");
    clone_command
        .args([
            "-c",
            &format!("e2ee.key={}", key_path.display()),
            "clone",
            "-q",
            &url,
        ])
        .arg(&clone);
    add_helper_to_path(&mut clone_command);
    let output = clone_command.output().unwrap();
    assert!(
        output.status.success(),
        "clone stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), source_head);
    assert_eq!(
        git(
            &clone,
            &["config", "--get", "remote.origin.e2ee-key"],
            false,
        ),
        key_path.to_string_lossy()
    );
    assert_eq!(
        fs::read_to_string(clone.join("note.md")).unwrap(),
        "carrier secret marker\n"
    );

    let grep = Command::new("git")
        .arg(format!("--git-dir={}", carrier.display()))
        .args([
            "grep",
            "-n",
            "carrier secret marker",
            "refs/heads/git-remote-e2ee",
        ])
        .output()
        .unwrap();
    assert_eq!(grep.status.code(), Some(1));
}

#[test]
fn carrier_git_allows_exactly_one_concurrent_writer() {
    let temporary = tempfile::tempdir().unwrap();
    let carrier = temporary.path().join("carrier.git");
    let source_a = temporary.path().join("source-a");
    let source_b = temporary.path().join("source-b");
    init_source(&source_a, "writer a secret");
    init_source(&source_b, "writer b secret");

    let key = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &key);

    // Open both carrier checkouts before either push. They therefore race from
    // the same outer commit and exercise receive-pack's ref lock/FF check.
    let repository_a = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        key.clone(),
    );
    let repository_b = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        key.clone(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let barrier_a = barrier.clone();
    let first = thread::spawn(move || {
        barrier_a.wait();
        repository_a.push_update(&source_a, "refs/heads/main", "refs/heads/writer-a", false)
    });
    let barrier_b = barrier.clone();
    let second = thread::spawn(move || {
        barrier_b.wait();
        repository_b.push_update(&source_b, "refs/heads/main", "refs/heads/writer-b", false)
    });

    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let loser = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .unwrap();
    assert!(
        loser.downcast_ref::<CasConflict>().is_some(),
        "unexpected losing error: {loser:#}"
    );

    let fresh = EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), key);
    let manifest = fresh.verify().unwrap();
    assert_eq!(manifest.generation, 1);
    assert_eq!(manifest.refs.len(), 1);
    assert_eq!(manifest.packs.len(), 1);
    assert_eq!(
        git(
            temporary.path(),
            &[
                &format!("--git-dir={}", carrier.display()),
                "rev-list",
                "--count",
                "refs/heads/git-remote-e2ee",
            ],
            false,
        ),
        "2"
    );
}

#[test]
fn native_fetch_rejects_outer_carrier_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let clone = temporary.path().join("clone");
    let key_path = temporary.path().join("repository.key.json");
    init_source(&source, "rollback generation one");
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    init_carrier(temporary.path(), &carrier, &key);

    let generation_zero = git(
        temporary.path(),
        &[
            &format!("--git-dir={}", carrier.display()),
            "rev-parse",
            "refs/heads/git-remote-e2ee",
        ],
        false,
    );
    let url = format!("e2ee::git+{}", carrier.display());
    git(&source, &["remote", "add", "private", &url], false);
    git(
        &source,
        &[
            "config",
            "remote.private.e2ee-key",
            key_path.to_str().unwrap(),
        ],
        false,
    );
    git(&source, &["push", "private", "main"], true);

    let mut clone_command = Command::new("git");
    clone_command
        .args([
            "-c",
            &format!("e2ee.key={}", key_path.display()),
            "clone",
            "-q",
            &url,
        ])
        .arg(&clone);
    add_helper_to_path(&mut clone_command);
    assert!(clone_command.output().unwrap().status.success());

    git(
        temporary.path(),
        &[
            &format!("--git-dir={}", carrier.display()),
            "update-ref",
            "refs/heads/git-remote-e2ee",
            &generation_zero,
        ],
        false,
    );
    let output = git_output(&clone, &["fetch", "origin"], true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rolled back"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn carrier_git_detects_tampered_ciphertext_chunk() {
    let temporary = tempfile::tempdir().unwrap();
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let attacker = temporary.path().join("attacker");
    init_source(&source, "tamper secret marker");
    let key = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &key);
    EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        key.clone(),
    )
    .push_ref(&source, "refs/heads/main", false)
    .unwrap();

    git(
        temporary.path(),
        &[
            "clone",
            "-q",
            "-b",
            "git-remote-e2ee",
            carrier.to_str().unwrap(),
            attacker.to_str().unwrap(),
        ],
        false,
    );
    git(&attacker, &["config", "user.name", "Attacker"], false);
    git(
        &attacker,
        &["config", "user.email", "attacker@example.invalid"],
        false,
    );
    let chunks = git(&attacker, &["ls-files", "e2ee/objects/*/*/*"], false);
    let chunk = chunks.lines().next().expect("encrypted pack chunk");
    let mut bytes = fs::read(attacker.join(chunk)).unwrap();
    bytes[0] ^= 0x80;
    fs::write(attacker.join(chunk), bytes).unwrap();
    git(&attacker, &["add", chunk], false);
    git(&attacker, &["commit", "-q", "-m", "tamper chunk"], false);
    git(
        &attacker,
        &["push", "-q", "origin", "git-remote-e2ee"],
        false,
    );

    let fresh = EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), key);
    let error = fresh.verify().unwrap_err();
    assert!(
        error.to_string().contains("pack ciphertext hash mismatch"),
        "unexpected verification error: {error:#}"
    );
}

#[test]
fn carrier_branch_coexists_with_unrelated_repository_history() {
    let temporary = tempfile::tempdir().unwrap();
    let carrier = temporary.path().join("carrier.git");
    let ordinary = temporary.path().join("ordinary");
    init_source(&ordinary, "ordinary public content");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    git(
        &ordinary,
        &["remote", "add", "origin", carrier.to_str().unwrap()],
        false,
    );
    git(&ordinary, &["push", "-q", "-u", "origin", "main"], false);
    let main_before = git(&ordinary, &["rev-parse", "HEAD"], false);

    let key = KeyFile::generate();
    let encrypted =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), key);
    encrypted.initialize().unwrap();
    assert!(
        encrypted
            .initialize()
            .unwrap_err()
            .to_string()
            .contains("already initialized")
    );

    assert_eq!(
        git(
            temporary.path(),
            &[
                &format!("--git-dir={}", carrier.display()),
                "rev-parse",
                "refs/heads/main",
            ],
            false,
        ),
        main_before
    );
    assert!(
        !git(
            temporary.path(),
            &[
                &format!("--git-dir={}", carrier.display()),
                "rev-parse",
                "refs/heads/git-remote-e2ee",
            ],
            false,
        )
        .is_empty()
    );
}
