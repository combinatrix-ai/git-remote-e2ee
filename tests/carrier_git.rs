use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use git_remote_e2ee::crypto::{KeyFile, object_id, random_key};
use git_remote_e2ee::manifest::{
    Manifest, ManifestAuthorization, open_manifest, peek_manifest_header, seal_manifest,
    unwrap_generation_key, wrap_predecessor_key,
};
use git_remote_e2ee::policy::{DeviceRoles, PolicyState};
use git_remote_e2ee::repository::{EncryptedRepository, RecoveryClass, RecoveryOptions};
use git_remote_e2ee::storage::{CasConflict, GitStorage, ObjectKind, Storage};

static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn isolated_cache(temporary: &tempfile::TempDir) -> MutexGuard<'static, ()> {
    let guard = CACHE_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = temporary.path().join("carrier-cache");
    // This test binary serializes all tests that open GitStorage, keeping the
    // process-global override stable while helper subprocesses inherit it.
    unsafe { env::set_var("GIT_REMOTE_E2EE_CACHE_DIR", cache) };
    guard
}

fn cache_repo(cache_root: &Path) -> std::path::PathBuf {
    let per_remote = fs::read_dir(cache_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("one per-remote carrier cache directory");
    let generation = fs::read_to_string(per_remote.join("current")).unwrap();
    per_remote.join(generation.trim())
}

fn reachable_object_count(repo: &Path) -> usize {
    let output = Command::new("git")
        .arg(format!("--git-dir={}", repo.display()))
        .args(["rev-list", "--objects", "--all"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git rev-list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().lines().count()
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

fn create_reader_signed_junk(
    storage: &GitStorage,
    reader: &KeyFile,
    policy: &PolicyState,
    parent_id: &str,
) -> String {
    let encrypted = storage.get_object(ObjectKind::Manifest, parent_id).unwrap();
    let header = peek_manifest_header(&encrypted).unwrap();
    let parent_key = unwrap_generation_key(&header, reader).unwrap();
    let opened = open_manifest(&encrypted, &parent_key).unwrap();
    let parent = opened.manifest();
    let generation_key = random_key();
    let manifest = Manifest {
        format_version: parent.format_version,
        repository_root: parent.repository_root.clone(),
        generation: parent.generation + 1,
        previous: Some(parent_id.to_owned()),
        policy_id: parent.policy_id.clone(),
        policy_generation: parent.policy_generation,
        authorization: ManifestAuthorization::Writer,
        total_pack_count: parent.total_pack_count,
        refs: parent.refs.clone(),
        new_packs: Vec::new(),
        predecessor_key_wrap: Some(
            wrap_predecessor_key(
                &generation_key,
                &parent_key,
                &parent.repository_root,
                parent.generation + 1,
                parent_id,
            )
            .unwrap(),
        ),
        introduced_policy: None,
    };
    let encrypted = seal_manifest(
        reader,
        policy,
        &generation_key,
        ManifestAuthorization::Writer,
        manifest,
    )
    .unwrap();
    let id = object_id(&encrypted);
    storage
        .put_object_if_absent(ObjectKind::Manifest, &id, &encrypted)
        .unwrap();
    id
}

fn create_writer_successor(
    storage: &GitStorage,
    writer: &KeyFile,
    policy: &PolicyState,
    parent_id: &str,
    refs: BTreeMap<String, String>,
) -> String {
    let encrypted = storage.get_object(ObjectKind::Manifest, parent_id).unwrap();
    let header = peek_manifest_header(&encrypted).unwrap();
    let parent_key = unwrap_generation_key(&header, writer).unwrap();
    let opened = open_manifest(&encrypted, &parent_key).unwrap();
    let parent = opened.manifest();
    let generation_key = random_key();
    let manifest = Manifest {
        format_version: parent.format_version,
        repository_root: parent.repository_root.clone(),
        generation: parent.generation + 1,
        previous: Some(parent_id.to_owned()),
        policy_id: parent.policy_id.clone(),
        policy_generation: parent.policy_generation,
        authorization: ManifestAuthorization::Writer,
        total_pack_count: parent.total_pack_count,
        refs,
        new_packs: Vec::new(),
        predecessor_key_wrap: Some(
            wrap_predecessor_key(
                &generation_key,
                &parent_key,
                &parent.repository_root,
                parent.generation + 1,
                parent_id,
            )
            .unwrap(),
        ),
        introduced_policy: None,
    };
    let encrypted = seal_manifest(
        writer,
        policy,
        &generation_key,
        ManifestAuthorization::Writer,
        manifest,
    )
    .unwrap();
    let id = object_id(&encrypted);
    storage
        .put_object_if_absent(ObjectKind::Manifest, &id, &encrypted)
        .unwrap();
    id
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
    let _cache = isolated_cache(&temporary);
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
    assert_eq!(
        git(
            &carrier,
            &["show", "refs/heads/git-remote-e2ee:.gitattributes"],
            false,
        ),
        "e2ee/** -delta"
    );

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
fn carrier_git_supports_tags_and_ref_deletion() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    let key_path = temporary.path().join("repository.key.json");
    let main = init_source(&source, "carrier refs");
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
    git(
        &source,
        &["tag", "-a", "v-carrier", "-m", "carrier release", &main],
        false,
    );
    git(&source, &["push", "private", "v-carrier"], true);

    let mut clone_command = Command::new("git");
    clone_command
        .args([
            "-c",
            &format!("e2ee.key={}", key_path.display()),
            "clone",
            "-q",
            &url,
        ])
        .arg(&returning);
    add_helper_to_path(&mut clone_command);
    let clone_output = clone_command.output().unwrap();
    assert!(
        clone_output.status.success(),
        "clone stdout={} stderr={}",
        String::from_utf8_lossy(&clone_output.stdout),
        String::from_utf8_lossy(&clone_output.stderr)
    );
    assert_eq!(
        git(
            &returning,
            &["cat-file", "-t", "refs/tags/v-carrier"],
            false
        ),
        "tag"
    );

    git(&source, &["switch", "-q", "-c", "doomed"], false);
    fs::write(source.join("note.md"), "branch to delete\n").unwrap();
    git(&source, &["add", "note.md"], false);
    git(&source, &["commit", "-q", "-m", "doomed"], false);
    git(&source, &["push", "private", "doomed"], true);
    git(&source, &["push", "--delete", "private", "doomed"], true);
    git(&source, &["push", "private", ":refs/tags/v-carrier"], true);
    git(
        &returning,
        &["fetch", "--prune", "--prune-tags", "origin"],
        true,
    );

    assert!(
        !git_output(
            &returning,
            &["show-ref", "--verify", "refs/remotes/origin/doomed"],
            false
        )
        .status
        .success()
    );
    assert!(
        !git_output(
            &returning,
            &["show-ref", "--verify", "refs/tags/v-carrier"],
            false
        )
        .status
        .success()
    );
    let manifest =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), key)
            .verify()
            .unwrap();
    assert!(!manifest.refs.contains_key("refs/heads/doomed"));
    assert!(!manifest.refs.contains_key("refs/tags/v-carrier"));
}

#[test]
fn carrier_git_allows_exactly_one_concurrent_writer() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
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
    assert_eq!(manifest.total_pack_count, 1);
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
fn carrier_cache_fetches_only_new_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let first = "1".repeat(64);
    let second = "2".repeat(64);

    let initial = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    initial.compare_and_swap_head(None, &first).unwrap();
    drop(initial);

    let cached = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let cache_root = temporary.path().join("carrier-cache");
    let cache = cache_repo(&cache_root);
    let before_push = reachable_object_count(&cache);
    let remote_before = reachable_object_count(&carrier);
    assert_eq!(before_push, remote_before);

    cached.compare_and_swap_head(Some(&first), &second).unwrap();
    drop(cached);
    let remote_after = reachable_object_count(&carrier);
    assert!(remote_after > remote_before);
    let after_push = reachable_object_count(&cache);
    assert_eq!(after_push, remote_after);

    let updated = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(after_push - before_push, remote_after - remote_before);
    assert_eq!(after_push, remote_after);
    drop(updated);

    let unchanged = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(reachable_object_count(&cache), after_push);
    drop(unchanged);
}

#[test]
fn carrier_cache_does_not_hide_remote_access_errors() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let missing_remote = temporary.path().join("missing-carrier.git");
    let error = match GitStorage::open(missing_remote.to_str().unwrap()) {
        Ok(_) => panic!("opening a missing carrier unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("fetch") || error.to_string().contains("ls-remote"),
        "unexpected remote error: {error:#}"
    );
}

#[test]
fn stale_carrier_cache_is_refreshed_before_compare_and_swap() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let stale = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let winner = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let winner_head = "3".repeat(64);
    let stale_head = "4".repeat(64);

    winner.compare_and_swap_head(None, &winner_head).unwrap();
    let error = stale.compare_and_swap_head(None, &stale_head).unwrap_err();
    let conflict = error.downcast_ref::<CasConflict>().unwrap();
    assert_eq!(conflict.actual.as_deref(), Some(winner_head.as_str()));

    let remote_head = git(
        temporary.path(),
        &[
            &format!("--git-dir={}", carrier.display()),
            "show",
            "refs/heads/git-remote-e2ee:e2ee/HEAD",
        ],
        false,
    );
    assert_eq!(remote_head, winner_head);
}

#[test]
fn deleted_and_corrupt_carrier_caches_are_rebuilt() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let head = "5".repeat(64);
    let storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    storage.compare_and_swap_head(None, &head).unwrap();
    drop(storage);

    let populated = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(
        populated.read_head().unwrap().as_deref(),
        Some(head.as_str())
    );
    drop(populated);
    let cache_root = temporary.path().join("carrier-cache");
    let cache = cache_repo(&cache_root);

    fs::remove_dir_all(&cache).unwrap();
    let rebuilt = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(rebuilt.read_head().unwrap().as_deref(), Some(head.as_str()));
    drop(rebuilt);

    let cache = cache_repo(&cache_root);
    let object_listing = git(&cache, &["rev-list", "--objects", "--all"], false);
    let object_id = object_listing
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .expect("fetched carrier commit");
    let loose_object = cache
        .join("objects")
        .join(&object_id[..2])
        .join(&object_id[2..]);
    if loose_object.exists() {
        // Unlink first because local Git transports may hard-link loose objects.
        fs::remove_file(&loose_object).unwrap();
        fs::write(&loose_object, b"corrupt cache object").unwrap();
    } else {
        let pack = fs::read_dir(cache.join("objects/pack"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "pack")
            })
            .expect("fetched carrier objects are packed");
        fs::write(pack, b"corrupt cache pack").unwrap();
    }

    let recovered = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(
        recovered.read_head().unwrap().as_deref(),
        Some(head.as_str())
    );
    assert_eq!(
        reachable_object_count(&cache_repo(&cache_root)),
        reachable_object_count(&carrier)
    );
}

#[test]
fn carrier_git_process_race_has_exactly_one_winner() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let ready_a = temporary.path().join("ready-a");
    let ready_b = temporary.path().join("ready-b");
    let result_a = temporary.path().join("result-a");
    let result_b = temporary.path().join("result-b");
    let start = temporary.path().join("start");
    let executable = env::current_exe().unwrap();
    let launch = |candidate: &str, ready: &Path, result: &Path| {
        Command::new(&executable)
            .args([
                "--ignored",
                "--exact",
                "carrier_git_process_race_worker",
                "--nocapture",
            ])
            .env("E2EE_TEST_RACE_REMOTE", &carrier)
            .env("E2EE_TEST_RACE_CANDIDATE", candidate)
            .env("E2EE_TEST_RACE_READY", ready)
            .env("E2EE_TEST_RACE_RESULT", result)
            .env("E2EE_TEST_RACE_START", &start)
            .spawn()
            .unwrap()
    };
    let first = launch(&"6".repeat(64), &ready_a, &result_a);
    let second = launch(&"7".repeat(64), &ready_b, &result_b);

    let deadline = Instant::now() + Duration::from_secs(10);
    while (!ready_a.exists() || !ready_b.exists()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready_a.exists() && ready_b.exists(),
        "race workers did not become ready"
    );
    fs::write(&start, "go").unwrap();

    let first_output = first.wait_with_output().unwrap();
    let second_output = second.wait_with_output().unwrap();
    assert!(
        first_output.status.success(),
        "first worker failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    assert!(
        second_output.status.success(),
        "second worker failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );
    let results = [
        fs::read_to_string(result_a).unwrap(),
        fs::read_to_string(result_b).unwrap(),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| result.as_str() == "winner")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.as_str() == "conflict")
            .count(),
        1
    );
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
        "1"
    );
}

#[test]
#[ignore = "launched as a separate process by carrier_git_process_race_has_exactly_one_winner"]
fn carrier_git_process_race_worker() {
    let Ok(remote) = env::var("E2EE_TEST_RACE_REMOTE") else {
        return;
    };
    let candidate = env::var("E2EE_TEST_RACE_CANDIDATE").unwrap();
    let ready = env::var("E2EE_TEST_RACE_READY").unwrap();
    let result = env::var("E2EE_TEST_RACE_RESULT").unwrap();
    let start = env::var("E2EE_TEST_RACE_START").unwrap();
    let storage = GitStorage::open(&remote).unwrap();
    fs::write(ready, "ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !Path::new(&start).exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Path::new(&start).exists(),
        "parent did not release CAS race"
    );
    let outcome = match storage.compare_and_swap_head(None, &candidate) {
        Ok(()) => "winner",
        Err(error) if error.downcast_ref::<CasConflict>().is_some() => "conflict",
        Err(error) => panic!("unexpected CAS race failure: {error:#}"),
    };
    fs::write(result, outcome).unwrap();
}

#[test]
fn native_fetch_rejects_outer_carrier_rollback() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
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
    let _cache = isolated_cache(&temporary);
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
        error.to_string().contains("invalid pack stream magic"),
        "unexpected verification error: {error:#}"
    );
}

#[test]
fn carrier_recovery_chooses_legitimate_descendant_and_restores_deleted_ciphertext() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    let fresh = temporary.path().join("fresh");
    let cache_root = temporary.path().join("carrier-cache");
    init_source(&source, "legitimate descendant content");
    init_source(&returning, "returning local content");
    init_source(&fresh, "fresh local content");

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (reader_policy_manifest, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    let policy_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let policy_encrypted = policy_storage
        .get_object(ObjectKind::Manifest, &reader_policy_manifest)
        .unwrap();
    let policy_header = peek_manifest_header(&policy_encrypted).unwrap();
    let policy_key = unwrap_generation_key(&policy_header, &reader).unwrap();
    let policy_manifest = open_manifest(&policy_encrypted, &policy_key).unwrap();
    let floor_policy = PolicyState::parse(
        policy_manifest
            .manifest()
            .introduced_policy
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let pushed_object = git(&source, &["rev-parse", "HEAD"], false);
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let (floor_id, floor_manifest) = repository.current_manifest().unwrap();
    let pack_id = floor_manifest.new_packs[0].id.clone();
    repository.fetch_into(&returning, "private").unwrap();
    let floor_generation: u64 = serde_json::from_slice::<serde_json::Value>(
        &fs::read(returning.join(".git/git-remote-e2ee/private/state.json")).unwrap(),
    )
    .unwrap()["generation"]
        .as_u64()
        .unwrap();
    assert_eq!(floor_manifest.generation, floor_generation);
    repository
        .revoke_device(&reader.device_id().unwrap(), &admin_pin)
        .unwrap();
    let (legitimate_id, legitimate) = repository.current_manifest().unwrap();
    assert_eq!(legitimate.refs["refs/heads/main"], pushed_object);

    let attacker = temporary.path().join("carrier-edit");
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
    git(&attacker, &["config", "user.name", "Carrier editor"], false);
    git(
        &attacker,
        &["config", "user.email", "carrier-editor@example.invalid"],
        false,
    );
    fs::remove_dir_all(
        attacker
            .join("e2ee/objects")
            .join(&pack_id[..2])
            .join(&pack_id),
    )
    .unwrap();
    fs::write(attacker.join("e2ee/HEAD"), format!("{floor_id}\n")).unwrap();
    git(&attacker, &["add", "-A", "e2ee"], false);
    git(
        &attacker,
        &["commit", "-q", "-m", "replay floor and delete pack"],
        false,
    );
    git(
        &attacker,
        &["push", "-q", "origin", "git-remote-e2ee"],
        false,
    );

    let replay_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk_id = create_reader_signed_junk(&replay_storage, &reader, &floor_policy, &floor_id);
    replay_storage
        .compare_and_swap_head(Some(&floor_id), &junk_id)
        .unwrap();

    let recovery_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let recoverer = EncryptedRepository::new(recovery_storage, owner.clone());
    let report = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: false,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(report.classification, RecoveryClass::Invalid);
    assert_eq!(report.default_base.as_deref(), Some(legitimate_id.as_str()));
    assert!(report.replays.contains(&floor_id));
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.manifest_id == legitimate_id)
    );

    let older_base = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: Some(&floor_id),
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert!(
        older_base
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("--discard-newer")
    );

    let recovered = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    let recovered_id = recovered.published_manifest.unwrap();
    let (current_id, manifest) = recoverer.current_manifest().unwrap();
    assert_eq!(current_id, recovered_id);
    assert_eq!(manifest.previous.as_deref(), Some(legitimate_id.as_str()));
    assert_eq!(manifest.generation, floor_generation + 2);
    assert_eq!(manifest.refs["refs/heads/main"], pushed_object);
    assert!(
        GitStorage::open(carrier.to_str().unwrap())
            .unwrap()
            .open_object(ObjectKind::Pack, &pack_id)
            .is_ok()
    );
    let recovered_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let recovered_bytes = recovered_storage
        .get_object(ObjectKind::Manifest, &current_id)
        .unwrap();
    let recovered_header = peek_manifest_header(&recovered_bytes).unwrap();
    assert!(unwrap_generation_key(&recovered_header, &reader).is_err());

    recoverer.fetch_into(&returning, "private").unwrap();
    recoverer.fetch_into(&fresh, "private").unwrap();
    assert_eq!(
        git(
            &fresh,
            &["show", "refs/remotes/private/main:note.md"],
            false
        ),
        "legitimate descendant content"
    );
    let carrier_head = Command::new("git")
        .arg(format!("--git-dir={}", carrier.display()))
        .args(["show", "refs/heads/git-remote-e2ee:e2ee/HEAD"])
        .output()
        .unwrap();
    assert!(carrier_head.status.success());
    assert_eq!(
        String::from_utf8(carrier_head.stdout).unwrap().trim(),
        current_id
    );
    assert!(cache_root.exists());
}

#[test]
fn carrier_recovery_offers_hidden_legitimate_content_descendant() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    let fresh = temporary.path().join("fresh");
    init_source(&source, "legitimate descendant content");
    init_source(&returning, "returning local content");
    init_source(&fresh, "fresh local content");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    let floor_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let floor_bytes = floor_storage
        .get_object(ObjectKind::Manifest, &floor_id)
        .unwrap();
    let floor_header = peek_manifest_header(&floor_bytes).unwrap();
    let floor_key = unwrap_generation_key(&floor_header, &reader).unwrap();
    let floor_opened = open_manifest(&floor_bytes, &floor_key).unwrap();
    let floor_policy = PolicyState::parse(
        floor_opened
            .manifest()
            .introduced_policy
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    repository.fetch_into(&returning, "private").unwrap();

    let pushed_object = git(&source, &["rev-parse", "HEAD"], false);
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let (legitimate_id, legitimate) = repository.current_manifest().unwrap();
    assert_eq!(legitimate.refs["refs/heads/main"], pushed_object);

    let attacker = temporary.path().join("carrier-edit");
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
    git(&attacker, &["config", "user.name", "Carrier editor"], false);
    git(
        &attacker,
        &["config", "user.email", "carrier-editor@example.invalid"],
        false,
    );
    fs::write(attacker.join("e2ee/HEAD"), format!("{floor_id}\n")).unwrap();
    git(&attacker, &["add", "-A", "e2ee"], false);
    git(&attacker, &["commit", "-q", "-m", "replay floor"], false);
    git(
        &attacker,
        &["push", "-q", "origin", "git-remote-e2ee"],
        false,
    );

    let replay_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk_id = create_reader_signed_junk(&replay_storage, &reader, &floor_policy, &floor_id);
    replay_storage
        .compare_and_swap_head(Some(&floor_id), &junk_id)
        .unwrap();

    let recoverer =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), owner);
    let report = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: false,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(report.classification, RecoveryClass::Invalid);
    assert_eq!(report.default_base.as_deref(), Some(legitimate_id.as_str()));
    assert!(report.replays.contains(&floor_id));
    assert!(report.candidates.iter().any(|candidate| {
        candidate.manifest_id == legitimate_id && candidate.generation == legitimate.generation
    }));

    let stale_choice = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: Some(&floor_id),
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert!(
        stale_choice
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("--discard-newer")
    );

    let recovered = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    let recovered_id = recovered.published_manifest.unwrap();
    let (head, manifest) = recoverer.current_manifest().unwrap();
    assert_eq!(head, recovered_id);
    assert_eq!(manifest.previous.as_deref(), Some(legitimate_id.as_str()));
    assert_eq!(manifest.refs["refs/heads/main"], pushed_object);
    recoverer.fetch_into(&returning, "private").unwrap();
    recoverer.fetch_into(&fresh, "private").unwrap();
    assert_eq!(
        git(
            &fresh,
            &["show", "refs/remotes/private/main:note.md"],
            false
        ),
        "legitimate descendant content"
    );
}

#[test]
fn carrier_recovery_refuses_history_with_a_merge_hiding_a_legitimate_state() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    init_source(&source, "legitimate content");
    init_source(&returning, "returning local content");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    let floor_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let floor_bytes = floor_storage
        .get_object(ObjectKind::Manifest, &floor_id)
        .unwrap();
    let floor_header = peek_manifest_header(&floor_bytes).unwrap();
    let floor_key = unwrap_generation_key(&floor_header, &reader).unwrap();
    let floor_opened = open_manifest(&floor_bytes, &floor_key).unwrap();
    let floor_policy = PolicyState::parse(
        floor_opened
            .manifest()
            .introduced_policy
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    repository.fetch_into(&returning, "private").unwrap();
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();

    // Put a replay of the floor on the first-parent path and the legitimate
    // tip on the second parent. The merge still fast-forwards the carrier.
    let attacker = temporary.path().join("carrier-edit");
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
    git(&attacker, &["config", "user.name", "Carrier editor"], false);
    git(
        &attacker,
        &["config", "user.email", "carrier-editor@example.invalid"],
        false,
    );
    git(
        &attacker,
        &["checkout", "-q", "-b", "side", "HEAD~1"],
        false,
    );
    git(
        &attacker,
        &["commit", "-q", "--allow-empty", "-m", "replay floor"],
        false,
    );
    git(
        &attacker,
        &[
            "merge",
            "-q",
            "--no-ff",
            "-s",
            "ours",
            "-m",
            "hide",
            "git-remote-e2ee",
        ],
        false,
    );
    git(
        &attacker,
        &["push", "-q", "origin", "side:git-remote-e2ee"],
        false,
    );

    let junk_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk_id = create_reader_signed_junk(&junk_storage, &reader, &floor_policy, &floor_id);
    junk_storage
        .compare_and_swap_head(Some(&floor_id), &junk_id)
        .unwrap();

    let recoverer =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), owner);
    let error = recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("merge commit"), "{error:#}");
    let after = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_eq!(
        after.read_head().unwrap().as_deref(),
        Some(junk_id.as_str())
    );
}

#[test]
fn carrier_recovery_refuses_conflicting_authenticated_descendants() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let returning = temporary.path().join("returning");
    init_source(&returning, "local state");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    repository.fetch_into(&returning, "private").unwrap();

    let policy_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let policy_encrypted = policy_storage
        .get_object(ObjectKind::Manifest, &floor_id)
        .unwrap();
    let policy_header = peek_manifest_header(&policy_encrypted).unwrap();
    let policy_key = unwrap_generation_key(&policy_header, &owner).unwrap();
    let policy_manifest = open_manifest(&policy_encrypted, &policy_key).unwrap();
    let policy = PolicyState::parse(
        policy_manifest
            .manifest()
            .introduced_policy
            .as_deref()
            .unwrap(),
    )
    .unwrap();

    let first_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let first_fork = create_writer_successor(
        &first_storage,
        &owner,
        &policy,
        &floor_id,
        BTreeMap::from([("refs/heads/main".to_owned(), "1".repeat(40))]),
    );
    first_storage
        .compare_and_swap_head(Some(&floor_id), &first_fork)
        .unwrap();
    let second_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let second_fork = create_writer_successor(
        &second_storage,
        &owner,
        &policy,
        &floor_id,
        BTreeMap::from([("refs/heads/main".to_owned(), "2".repeat(40))]),
    );
    second_storage
        .compare_and_swap_head(Some(&first_fork), &second_fork)
        .unwrap();
    let junk_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk = create_reader_signed_junk(&junk_storage, &reader, &policy, &floor_id);
    junk_storage
        .compare_and_swap_head(Some(&second_fork), &junk)
        .unwrap();

    let recovery_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let report = EncryptedRepository::new(recovery_storage, owner)
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(report.classification, RecoveryClass::Invalid);
    assert!(report.conflict);
    assert!(
        report
            .blocked_reason
            .as_deref()
            .unwrap()
            .contains("refusing to choose between forks")
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.manifest_id == first_fork)
    );
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.manifest_id == second_fork)
    );
    let current = GitStorage::open(carrier.to_str().unwrap())
        .unwrap()
        .read_head()
        .unwrap();
    assert_eq!(current.as_deref(), Some(junk.as_str()));
}

#[test]
fn carrier_recovery_loses_cas_without_retrying_when_another_writer_publishes() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let returning = temporary.path().join("returning");
    init_source(&returning, "local state");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );

    let owner = KeyFile::generate();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            DeviceRoles::reader(),
            &admin_pin,
        )
        .unwrap();
    repository.fetch_into(&returning, "private").unwrap();
    let policy_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let policy_encrypted = policy_storage
        .get_object(ObjectKind::Manifest, &floor_id)
        .unwrap();
    let policy_header = peek_manifest_header(&policy_encrypted).unwrap();
    let policy_key = unwrap_generation_key(&policy_header, &reader).unwrap();
    let policy_manifest = open_manifest(&policy_encrypted, &policy_key).unwrap();
    let policy = PolicyState::parse(
        policy_manifest
            .manifest()
            .introduced_policy
            .as_deref()
            .unwrap(),
    )
    .unwrap();

    let bad_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk = create_reader_signed_junk(&bad_storage, &reader, &policy, &floor_id);
    bad_storage
        .compare_and_swap_head(Some(&floor_id), &junk)
        .unwrap();
    let stale_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let stale_recoverer = EncryptedRepository::new(stale_storage, owner.clone());
    let offered = stale_recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: false,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap();
    assert_eq!(offered.classification, RecoveryClass::Invalid);
    assert_eq!(offered.default_base.as_deref(), Some(floor_id.as_str()));

    let competing_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let winner = create_writer_successor(
        &competing_storage,
        &owner,
        &policy,
        &floor_id,
        BTreeMap::new(),
    );
    competing_storage
        .compare_and_swap_head(Some(&junk), &winner)
        .unwrap();

    let error = stale_recoverer
        .recover(
            &returning,
            "private",
            RecoveryOptions {
                publish: true,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("concurrently"));
    let latest =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), owner);
    assert_eq!(latest.current_manifest().unwrap().0, winner);
}

#[test]
fn carrier_branch_coexists_with_unrelated_repository_history() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
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
