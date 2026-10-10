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
fn lightweight_annotated_and_followed_tags_round_trip_through_helper() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let before_tags = temporary.path().join("before-tags");
    initialize_git(&source);
    let (storage, key_path, key) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);
    let first = commit_file(&source, "first", "first");
    git(&source, &["push", "private", "main"], true);
    clone_remote(&before_tags, &storage, &key_path);

    git(&source, &["tag", "v1.0", &first], false);
    git(&source, &["push", "private", "v1.0"], true);
    git(
        &source,
        &["tag", "-a", "v1.1", "-m", "release one", &first],
        false,
    );
    fs::write(source.join("tag-target.bin"), b"tagged blob object\n").unwrap();
    let blob = git(&source, &["hash-object", "-w", "tag-target.bin"], false);
    git(&source, &["add", "tag-target.bin"], false);
    let tree = git(&source, &["write-tree"], false);
    git(
        &source,
        &["tag", "-a", "v-blob", "-m", "blob target", &blob],
        false,
    );
    git(
        &source,
        &["tag", "-a", "v-tree", "-m", "tree target", &tree],
        false,
    );
    git(&source, &["push", "--tags", "private"], true);

    git(&before_tags, &["fetch", "--tags", "origin"], true);
    assert_eq!(
        git(&before_tags, &["rev-parse", "refs/tags/v1.0"], false),
        first
    );
    assert_eq!(
        git(&before_tags, &["cat-file", "-t", "refs/tags/v1.1"], false),
        "tag"
    );
    assert_eq!(
        git(&before_tags, &["rev-parse", "refs/tags/v1.1^{}"], false),
        first
    );
    assert_eq!(
        git(&before_tags, &["cat-file", "-t", "refs/tags/v-blob"], false),
        "tag"
    );
    assert_eq!(
        git(&before_tags, &["rev-parse", "refs/tags/v-blob^{}"], false),
        blob
    );
    git(&before_tags, &["cat-file", "-e", &blob], false);
    assert_eq!(
        git(&before_tags, &["rev-parse", "refs/tags/v-tree^{}"], false),
        tree
    );
    assert_eq!(git(&before_tags, &["cat-file", "-t", &tree], false), "tree");

    let second = commit_file(&source, "second", "second");
    git(
        &source,
        &["tag", "-a", "v2.0", "-m", "release two", &second],
        false,
    );
    git(&source, &["push", "--follow-tags", "private", "main"], true);

    let repository = EncryptedRepository::new(FilesystemStorage::new(&storage), key);
    let manifest = repository.verify().unwrap();
    assert_eq!(manifest.refs["refs/tags/v1.0"], first);
    assert_eq!(
        manifest.refs["refs/tags/v1.1"],
        git(&source, &["rev-parse", "refs/tags/v1.1"], false)
    );
    assert_eq!(
        manifest.refs["refs/tags/v2.0"],
        git(&source, &["rev-parse", "refs/tags/v2.0"], false)
    );

    let fresh = temporary.path().join("fresh-clone");
    clone_remote(
        &fresh,
        &storage,
        &temporary.path().join("repository.key.json"),
    );
    assert_eq!(
        git(&fresh, &["cat-file", "-t", "refs/tags/v1.1"], false),
        "tag"
    );
    assert_eq!(
        git(&fresh, &["cat-file", "-t", "refs/tags/v2.0"], false),
        "tag"
    );
    assert_eq!(
        git(&fresh, &["rev-parse", "refs/tags/v2.0^{}"], false),
        second
    );
}

#[test]
fn moving_an_existing_tag_requires_force() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    initialize_git(&source);
    let (storage, key_path, key) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);
    let first = commit_file(&source, "first", "first");
    git(&source, &["push", "private", "main"], true);
    git(&source, &["tag", "v1.0", &first], false);
    git(&source, &["push", "private", "v1.0"], true);

    let second = commit_file(&source, "second", "second");
    git(&source, &["push", "private", "main"], true);
    git(&source, &["tag", "-f", "v1.0", &second], false);
    let repository = EncryptedRepository::new(FilesystemStorage::new(&storage), key);
    let before = repository.verify().unwrap();
    let rejected = git_output(&source, &["push", "private", "v1.0"], true);
    assert!(!rejected.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(message.contains("already exists"), "{message}");
    let after_rejection = repository.verify().unwrap();
    assert_eq!(after_rejection.generation, before.generation);
    assert_eq!(after_rejection.refs["refs/tags/v1.0"], first);

    git(&source, &["push", "--force", "private", "v1.0"], true);
    assert_eq!(repository.verify().unwrap().refs["refs/tags/v1.0"], second);
}

#[test]
fn deletions_publish_without_packs_and_prune_on_returning_and_fresh_clones() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning-clone");
    initialize_git(&source);
    let (storage, key_path, key) = setup_remote(temporary.path());
    configure_remote(&source, &storage, &key_path);
    let main = commit_file(&source, "main", "main");
    git(&source, &["push", "private", "main"], true);
    git(&source, &["branch", "doomed", &main], false);
    git(&source, &["push", "private", "doomed"], true);
    git(&source, &["tag", "v-delete", &main], false);
    git(&source, &["push", "private", "v-delete"], true);
    clone_remote(&returning, &storage, &key_path);

    let repository = EncryptedRepository::new(FilesystemStorage::new(&storage), key);
    let before = repository.verify().unwrap();
    let default_delete = git_output(&source, &["push", "--delete", "private", "main"], true);
    assert!(!default_delete.status.success());
    let default_error = format!(
        "{}{}",
        String::from_utf8_lossy(&default_delete.stdout),
        String::from_utf8_lossy(&default_delete.stderr)
    );
    assert!(
        default_error.contains("remote default branch"),
        "{default_error}"
    );
    assert_eq!(repository.verify().unwrap().generation, before.generation);

    git(&source, &["push", "--delete", "private", "doomed"], true);
    let after_branch_delete = repository.verify().unwrap();
    assert!(!after_branch_delete.refs.contains_key("refs/heads/doomed"));
    assert_eq!(
        after_branch_delete.total_pack_count,
        before.total_pack_count
    );

    git(&source, &["push", "private", ":refs/tags/v-delete"], true);
    let after_tag_delete = repository.verify().unwrap();
    assert!(!after_tag_delete.refs.contains_key("refs/tags/v-delete"));
    assert_eq!(after_tag_delete.total_pack_count, before.total_pack_count);

    git(
        &returning,
        &["fetch", "--prune", "--prune-tags", "origin"],
        true,
    );
    assert!(
        git_output(
            &returning,
            &["show-ref", "--verify", "refs/remotes/origin/doomed"],
            false
        )
        .status
        .code()
        .is_some_and(|code| code != 0)
    );
    assert!(
        git_output(
            &returning,
            &["show-ref", "--verify", "refs/tags/v-delete"],
            false
        )
        .status
        .code()
        .is_some_and(|code| code != 0)
    );

    let fresh = temporary.path().join("fresh-clone");
    clone_remote(&fresh, &storage, &key_path);
    assert!(
        !git_output(
            &fresh,
            &["show-ref", "--verify", "refs/remotes/origin/doomed"],
            false
        )
        .status
        .success()
    );
    assert!(
        !git_output(
            &fresh,
            &["show-ref", "--verify", "refs/tags/v-delete"],
            false
        )
        .status
        .success()
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

    let namespace = git_output(
        &source,
        &["push", "private", "HEAD:refs/notes/review"],
        true,
    );
    assert!(!namespace.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&namespace.stdout),
        String::from_utf8_lossy(&namespace.stderr)
    );
    assert!(message.contains("unsupported ref namespace"), "{message}");
    let after_namespace = repository.verify().unwrap();
    assert_eq!(after_namespace.generation, generation);
    assert!(!after_namespace.refs.contains_key("refs/notes/review"));
}
