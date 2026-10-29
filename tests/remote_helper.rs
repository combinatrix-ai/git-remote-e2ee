use git_remote_e2ee::gitcmd::GitRepository;
mod support;
use support::PushRef;

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::{EncryptedRepository, RefChange};
use git_remote_e2ee::storage::FilesystemStorage;

fn git_output(repo: &Path, args: &[&str], with_helper: bool) -> Output {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo).args(args);
    if with_helper {
        let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
        let mut paths = vec![helper.parent().unwrap().to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        command
            .env("PATH", env::join_paths(paths).unwrap())
            .env("XDG_STATE_HOME", support::state_home());
    }
    command.output().unwrap()
}

fn state_dir(repo: &Path) -> std::path::PathBuf {
    let entries: Vec<_> = fs::read_dir(repo.join(".git/git-remote-e2ee"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries.into_iter().next().unwrap()
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
    let remote_url = format!("e2ee::dir:{}", remote_path.display());
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
    EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    )
    .initialize("owner")
    .unwrap();

    fs::write(source.join("note.md"), "through native Git\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    let source_head = git(&source, &["rev-parse", "HEAD"], false);

    let remote_url = format!("e2ee::dir:{}", remote_path.display());
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
fn concurrent_helper_processes_preserve_the_client_state_floor() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let stale_remote = temporary.path().join("stale-remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);
    encrypted
        .fetch_into(&GitRepository::open(&destination).unwrap(), "private")
        .unwrap();

    fs::write(source.join("note.md"), "first\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "first"], false);
    git(&source, &["push", "private", "main"], true);
    let stale_object = git(&source, &["rev-parse", "HEAD"], false);
    copy_tree(&remote_path, &stale_remote);

    fs::write(source.join("note.md"), "second\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "second"], false);
    let advertised_object = git(&source, &["rev-parse", "HEAD"], false);
    git(&source, &["push", "private", "main"], true);
    let (expected_head, expected_manifest) = encrypted.current_manifest().unwrap();

    let current_url = format!("e2ee::dir:{}", remote_path.display());
    let stale_url = format!("e2ee::dir:{}", stale_remote.display());
    let helper = env!("CARGO_BIN_EXE_git-remote-e2ee");
    let mut children = Vec::new();
    for remote_url in [&stale_url, &stale_url, &current_url, &current_url] {
        children.push(
            Command::new(helper)
                .arg("private")
                .arg(remote_url)
                .current_dir(&destination)
                .env("XDG_STATE_HOME", support::state_home())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for (index, child) in children.iter_mut().enumerate() {
        let object = if index < 2 {
            &stale_object
        } else {
            &advertised_object
        };
        let protocol = format!("capabilities\nlist\n\nfetch {object} refs/heads/main\n\n");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(protocol.as_bytes())
            .unwrap();
    }
    let mut current_successes = 0;
    for (index, child) in children.into_iter().enumerate() {
        let output = child.wait_with_output().unwrap();
        if index >= 2 {
            assert!(
                output.status.success(),
                "current helper failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            current_successes += 1;
        } else if !output.status.success() {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("rolled back"),
                "stale helper failed unexpectedly: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    assert_eq!(current_successes, 2);

    let progress_path = state_dir(&destination).join("progress.json");
    let progress: serde_json::Value =
        serde_json::from_slice(&fs::read(progress_path).unwrap()).unwrap();
    assert_eq!(
        progress["imported_generation"],
        expected_manifest.generation
    );
    let floor = support::read_floor(&expected_manifest.repository_root);
    assert_eq!(floor["generation"], expected_manifest.generation);
    assert_eq!(floor["head_id"], expected_head);
}

#[test]
fn native_git_dry_run_batch_does_not_mutate_remote() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();

    fs::write(source.join("note.md"), "dry run only\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    let remote_url = format!("e2ee::dir:{}", remote_path.display());
    let key_path = key_path.to_string_lossy();
    git(&source, &["remote", "add", "private", &remote_url], false);
    git(
        &source,
        &["config", "remote.private.e2ee-key", &key_path],
        false,
    );

    git(&source, &["branch", "feature"], false);
    git(&source, &["tag", "-a", "v1", "-m", "v1"], false);
    git(
        &source,
        &["push", "--dry-run", "private", "main", "feature", "v1"],
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
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
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
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
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
    assert_eq!(
        fs::read_to_string(remote_path.join("HEAD")).unwrap().trim(),
        first_remote_head
    );
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
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key.clone(),
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    fs::write(source.join("note.md"), "same object, different manifest\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "initial"], false);
    git(&source, &["push", "private", "main"], true);
    git(&destination, &["fetch", "private"], true);

    let fork = EncryptedRepository::new(
        FilesystemStorage::new(&fork_path),
        key,
        temporary.path().join("forker-machine"),
    );
    fork.initialize("owner").unwrap();
    let fork_head = fork
        .push_ref(
            &GitRepository::open(&source).unwrap(),
            "refs/heads/main",
            RefChange::Update {
                source: "refs/heads/main",
                force: false,
            },
        )
        .unwrap();
    copy_tree(&fork_path.join("manifests"), &remote_path.join("manifests"));
    fs::write(remote_path.join("HEAD"), format!("{fork_head}\n")).unwrap();

    let output = git_output(&destination, &["fetch", "private"], true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("history forked"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_git_fetch_pins_membership_changes_that_transfer_no_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let extra = KeyFile::generate_for_repository(key.repository_root.clone()).unwrap();
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    fs::write(source.join("note.md"), "first\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "first"], false);
    git(&source, &["push", "private", "main"], true);
    git(&destination, &["fetch", "private"], true);
    let before_membership_change = encrypted.current_manifest().unwrap().0;

    // A membership change publishes a new generation without changing refs, so
    // Git finds nothing to transfer and never sends the helper a fetch command.
    encrypted
        .add_device(
            extra.public_device().unwrap(),
            "device-1",
            DeviceRoles::reader(),
        )
        .unwrap();
    git(&destination, &["fetch", "private"], true);

    fs::write(
        remote_path.join("HEAD"),
        format!("{before_membership_change}\n"),
    )
    .unwrap();
    let output = git_output(&destination, &["fetch", "private"], true);
    assert!(
        !output.status.success(),
        "replaying the pre-change manifest must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rolled back"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_git_fetch_pins_branch_deletions_that_transfer_no_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);

    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    fs::write(source.join("note.md"), "first\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "first"], false);
    git(&source, &["branch", "feature"], false);
    git(&source, &["push", "private", "main", "feature"], true);
    git(&destination, &["fetch", "private"], true);
    let before_deletion = encrypted.current_manifest().unwrap().0;

    git(&source, &["push", "private", "--delete", "feature"], true);
    git(&destination, &["fetch", "--prune", "private"], true);

    fs::write(remote_path.join("HEAD"), format!("{before_deletion}\n")).unwrap();
    let output = git_output(&destination, &["fetch", "private"], true);
    assert!(
        !output.status.success(),
        "replaying the pre-deletion manifest must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rolled back"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn native_git_fetch_reimports_packs_after_local_objects_are_pruned() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    initialize_git(&destination);
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    )
    .initialize("owner")
    .unwrap();
    configure_remote(&source, &remote_path, &key_path);
    configure_remote(&destination, &remote_path, &key_path);

    let helper_git = |repo: &Path, args: &[&str]| {
        let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
        let mut paths = vec![helper.parent().unwrap().to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("PATH", env::join_paths(paths).unwrap())
            .env("GIT_REMOTE_E2EE_CACHE_DIR", temporary.path().join("cache"))
            .env("XDG_STATE_HOME", temporary.path().join("state"))
            .env("XDG_CONFIG_HOME", temporary.path().join("config"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let mut heads = Vec::new();
    for (branch, content) in [("main", "first"), ("feature", "second")] {
        git(&source, &["checkout", "-q", "-B", branch], false);
        fs::write(source.join("note.md"), format!("{content}\n")).unwrap();
        git(&source, &["add", "note.md"], false);
        git(&source, &["commit", "-q", "-m", content], false);
        heads.push(git(&source, &["rev-parse", "HEAD"], false));
        helper_git(&source, &["push", "-q", "private", branch]);
    }

    // Git may run detached auto-maintenance after a fetch, which can repack
    // or prune concurrently with the explicit prune below and make the test
    // nondeterministic on fast CI runners. Disable it and prune explicitly.
    for setting in [
        "maintenance.auto=false",
        "gc.auto=0",
        "gc.autoDetach=false",
        "fetch.writeCommitGraph=false",
    ] {
        let (key, value) = setting.split_once('=').unwrap();
        git(&destination, &["config", key, value], false);
    }
    helper_git(&destination, &["fetch", "-q", "private"]);
    git(
        &destination,
        &["update-ref", "-d", "refs/remotes/private/feature"],
        false,
    );
    git(&destination, &["repack", "-a", "-d", "-q"], false);
    git(&destination, &["prune", "--expire=now"], false);
    assert!(
        !git_output(&destination, &["cat-file", "-e", &heads[1]], false)
            .status
            .success(),
        "gc pruned the feature commit"
    );

    helper_git(&destination, &["fetch", "-q", "private"]);
    assert_eq!(
        git(
            &destination,
            &["rev-parse", "refs/remotes/private/feature"],
            false
        ),
        heads[1]
    );
    git(
        &destination,
        &["fsck", "--connectivity-only", "--no-dangling"],
        false,
    );
    assert_eq!(
        git(
            &destination,
            &["show", "refs/remotes/private/feature:note.md"],
            false
        ),
        "second"
    );
}

struct Helper {
    _temporary: tempfile::TempDir,
    source: std::path::PathBuf,
    remote_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    encrypted: EncryptedRepository<FilesystemStorage>,
}

fn helper_repository() -> Helper {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let remote_path = temporary.path().join("remote");
    let key_path = temporary.path().join("repository.key.json");
    initialize_git(&source);
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    let encrypted = EncryptedRepository::new(
        FilesystemStorage::new(&remote_path),
        key,
        support::state_dir(),
    );
    encrypted.initialize("owner").unwrap();
    configure_remote(&source, &remote_path, &key_path);
    Helper {
        _temporary: temporary,
        source,
        remote_path,
        key_path,
        encrypted,
    }
}

fn commit_file(repo: &Path, name: &str, contents: &[u8], message: &str) -> String {
    fs::write(repo.join(name), contents).unwrap();
    git(repo, &["add", name], false);
    git(repo, &["commit", "-q", "-m", message], false);
    git(repo, &["rev-parse", "HEAD"], false)
}

/// A fresh repository fetching every branch and tag from the helper's storage.
fn fresh_clone(helper: &Helper) -> std::path::PathBuf {
    let clone = helper.source.with_file_name("fresh-clone");
    initialize_git(&clone);
    configure_remote(&clone, &helper.remote_path, &helper.key_path);
    git(&clone, &["fetch", "-q", "--tags", "private"], true);
    clone
}

#[test]
fn native_git_push_of_many_refs_publishes_one_generation() {
    let helper = helper_repository();
    let source = &helper.source;
    commit_file(source, "note.md", b"first\n", "first");
    git(source, &["tag", "light"], false);
    let main = commit_file(source, "note.md", b"second\n", "second");
    git(source, &["branch", "feature"], false);
    git(
        source,
        &["tag", "-a", "annotated", "-m", "annotated"],
        false,
    );
    git(source, &["checkout", "-q", "-b", "topic"], false);
    let topic = commit_file(source, "topic.md", b"topic\n", "topic");

    git(
        source,
        &[
            "push", "-q", "private", "main", "feature", "topic", "--tags",
        ],
        true,
    );

    let manifest = helper.encrypted.verify().unwrap();
    assert_eq!(manifest.generation, 1);
    assert_eq!(manifest.total_pack_count, 1);
    assert_eq!(manifest.refs.len(), 5, "{:?}", manifest.refs);
    let clone = fresh_clone(&helper);
    for (reference, expected) in [
        ("refs/remotes/private/main", &main),
        ("refs/remotes/private/feature", &main),
        ("refs/remotes/private/topic", &topic),
        (
            "refs/tags/light",
            &git(source, &["rev-parse", "light"], false),
        ),
        (
            "refs/tags/annotated",
            &git(source, &["rev-parse", "annotated"], false),
        ),
    ] {
        assert_eq!(&git(&clone, &["rev-parse", reference], false), expected);
    }
    git(
        &clone,
        &["fsck", "--connectivity-only", "--no-dangling"],
        false,
    );
}

#[test]
fn helper_push_batch_reports_rejected_refs_and_publishes_the_rest_once() {
    let helper = helper_repository();
    let source = &helper.source;
    commit_file(source, "note.md", b"first\n", "first");
    git(source, &["tag", "v1"], false);
    git(source, &["push", "-q", "private", "main", "v1"], true);
    let parent = helper.encrypted.verify().unwrap();

    git(
        source,
        &["commit", "-q", "--amend", "-m", "rewritten"],
        false,
    );
    git(source, &["tag", "-f", "v1"], false);
    git(source, &["branch", "topic"], false);
    let url = format!("e2ee::dir:{}", helper.remote_path.display());
    let output = Command::new(env!("CARGO_BIN_EXE_git-remote-e2ee"))
        .args(["private", &url])
        .current_dir(source)
        .env("XDG_STATE_HOME", support::state_home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(
                b"push refs/heads/main:refs/heads/main\n\
                  push refs/tags/v1:refs/tags/v1\n\
                  push refs/heads/topic:refs/heads/topic\n\n",
            )?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "error refs/heads/main non-fast forward\n\
         error refs/tags/v1 already exists\n\
         ok refs/heads/topic\n\n"
    );

    let manifest = helper.encrypted.verify().unwrap();
    assert_eq!(manifest.generation, parent.generation + 1);
    let mut expected = parent.refs.clone();
    expected.insert(
        "refs/heads/topic".to_owned(),
        git(source, &["rev-parse", "topic"], false),
    );
    assert_eq!(manifest.refs, expected);
}

#[test]
fn native_git_force_push_packs_only_the_rewritten_commits() {
    let helper = helper_repository();
    let source = &helper.source;
    // Distinct incompressible blobs, so the full history's pack is large.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for index in 0..20 {
        let blob: Vec<u8> = (0..16 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        commit_file(source, &format!("blob-{index}"), &blob, "history");
    }
    git(source, &["push", "-q", "private", "main"], true);
    let history_pack = helper.encrypted.verify().unwrap().new_packs[0].plaintext_size;

    git(source, &["reset", "-q", "--hard", "HEAD~1"], false);
    let forced = commit_file(source, "note.md", b"rewritten\n", "rewritten");
    git(source, &["push", "-q", "--force", "private", "main"], true);

    let manifest = helper.encrypted.verify().unwrap();
    assert_eq!(manifest.generation, 2);
    let forced_pack = manifest.new_packs[0].plaintext_size;
    assert!(
        forced_pack * 50 < history_pack,
        "force push packed {forced_pack} bytes against a {history_pack}-byte history"
    );
    let clone = fresh_clone(&helper);
    assert_eq!(
        git(&clone, &["rev-parse", "refs/remotes/private/main"], false),
        forced
    );
    git(
        &clone,
        &["fsck", "--connectivity-only", "--no-dangling"],
        false,
    );
}
