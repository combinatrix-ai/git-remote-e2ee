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
    .initialize("owner")
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

fn state_dir(repo: &Path) -> std::path::PathBuf {
    let entries: Vec<_> = fs::read_dir(repo.join(".git/git-remote-e2ee"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries.into_iter().next().unwrap()
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

    let url = format!("e2ee::{}", carrier.display());
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
        git(&carrier, &["show", "refs/heads/main:.gitattributes"], false,),
        "* -delta"
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
        .args(["grep", "-n", "carrier secret marker", "refs/heads/main"])
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

    let url = format!("e2ee::{}", carrier.display());
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
                "refs/heads/main",
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
            "refs/heads/main:HEAD",
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
                "refs/heads/main",
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
            "refs/heads/main",
        ],
        false,
    );
    let url = format!("e2ee::{}", carrier.display());
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
            "refs/heads/main",
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
            "main",
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
    let chunks = git(&attacker, &["ls-files", "packs/*/*/*"], false);
    let chunk = chunks.lines().next().expect("encrypted pack chunk");
    let mut bytes = fs::read(attacker.join(chunk)).unwrap();
    bytes[0] ^= 0x80;
    fs::write(attacker.join(chunk), bytes).unwrap();
    git(&attacker, &["add", chunk], false);
    git(&attacker, &["commit", "-q", "-m", "tamper chunk"], false);
    git(&attacker, &["push", "-q", "origin", "main"], false);

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
    repository.initialize("owner").unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (reader_policy_manifest, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            "device-1",
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
        &fs::read(state_dir(&returning).join("state.json")).unwrap(),
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
            "main",
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
    fs::remove_dir_all(attacker.join("packs").join(&pack_id[..2]).join(&pack_id)).unwrap();
    fs::write(attacker.join("HEAD"), format!("{floor_id}\n")).unwrap();
    git(&attacker, &["add", "-A", "."], false);
    git(
        &attacker,
        &["commit", "-q", "-m", "replay floor and delete pack"],
        false,
    );
    git(&attacker, &["push", "-q", "origin", "main"], false);

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
        .args(["show", "refs/heads/main:HEAD"])
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
    repository.initialize("owner").unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            "device-2",
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
            "main",
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
    fs::write(attacker.join("HEAD"), format!("{floor_id}\n")).unwrap();
    git(&attacker, &["add", "-A", "."], false);
    git(&attacker, &["commit", "-q", "-m", "replay floor"], false);
    git(&attacker, &["push", "-q", "origin", "main"], false);

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
    repository.initialize("owner").unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            "device-3",
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
            "main",
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
        &["merge", "-q", "--no-ff", "-s", "ours", "-m", "hide", "main"],
        false,
    );
    git(&attacker, &["push", "-q", "origin", "side:main"], false);

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
    repository.initialize("owner").unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            "device-4",
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
    repository.initialize("owner").unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    let (floor_id, _) = repository
        .add_device(
            reader.public_device().unwrap(),
            "device-5",
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

fn carrier_refs(carrier: &Path) -> String {
    git(
        carrier,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
        false,
    )
}

fn helper_command(cwd: &Path, home: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(cwd)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CONFIG_HOME", home.join("config"));
    add_helper_to_path(&mut command);
    command
}

fn assert_success(output: Output, action: &str) {
    assert!(
        output.status.success(),
        "{action}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn push_through_helper(source: &Path, url: &str, key_path: &Path, home: &Path) {
    git(source, &["remote", "add", "private", url], false);
    git(
        source,
        &[
            "config",
            "remote.private.e2ee-key",
            key_path.to_str().unwrap(),
        ],
        false,
    );
    assert_success(
        helper_command(source, home)
            .args(["push", "-q", "private", "main"])
            .output()
            .unwrap(),
        "push through helper",
    );
}

/// Commits a plain edit to a carrier branch, as a storage-level writer could.
fn edit_carrier(carrier: &Path, workdir: &Path, edit: impl FnOnce(&Path)) {
    if workdir.exists() {
        fs::remove_dir_all(workdir).unwrap();
    }
    git(
        carrier.parent().unwrap(),
        &[
            "clone",
            "-q",
            "-b",
            "main",
            carrier.to_str().unwrap(),
            workdir.to_str().unwrap(),
        ],
        false,
    );
    git(workdir, &["config", "user.name", "Carrier editor"], false);
    git(
        workdir,
        &["config", "user.email", "carrier-editor@example.invalid"],
        false,
    );
    edit(workdir);
    git(workdir, &["add", "-A", "."], false);
    git(workdir, &["commit", "-q", "-m", "edit carrier"], false);
    git(workdir, &["push", "-q", "origin", "main"], false);
}

#[test]
fn carrier_root_holds_exactly_the_v6_layout() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let key_path = temporary.path().join("repository.key.json");
    init_source(&source, "layout marker");
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    init_carrier(temporary.path(), &carrier, &key);
    let url = format!("e2ee::{}", carrier.display());
    push_through_helper(&source, &url, &key_path, temporary.path());

    let entries = git(
        &carrier,
        &["ls-tree", "--name-only", "refs/heads/main"],
        false,
    );
    assert_eq!(
        entries.lines().collect::<Vec<_>>(),
        [
            ".gitattributes",
            "FORMAT",
            "HEAD",
            "README.md",
            "manifests",
            "packs"
        ]
    );
    let blob = |name: &str| {
        git_output(
            &carrier,
            &["cat-file", "blob", &format!("refs/heads/main:{name}")],
            false,
        )
        .stdout
    };
    assert_eq!(blob("FORMAT"), b"git-remote-e2ee storage 6\n");
    assert_eq!(blob(".gitattributes"), b"* -delta\n");
    let readme = String::from_utf8(blob("README.md")).unwrap();
    assert!(readme.starts_with("# Encrypted Git repository\n\nThis branch holds"));
    assert!(readme.contains("git -c e2ee.key=<your device key> clone e2ee::"));
    assert!(
        !git(
            &carrier,
            &["ls-tree", "--name-only", "refs/heads/main", "packs/"],
            false
        )
        .is_empty()
    );
}

#[test]
fn carrier_format_mismatch_names_the_found_format() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let workdir = temporary.path().join("carrier-edit");
    let key = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &key);
    let read_error = || {
        let repository = EncryptedRepository::new(
            GitStorage::open(carrier.to_str().unwrap()).unwrap(),
            key.clone(),
        );
        format!("{:#}", repository.current_manifest().unwrap_err())
    };

    edit_carrier(&carrier, &workdir, |root| {
        fs::write(root.join("FORMAT"), "git-remote-e2ee storage 7\n").unwrap();
    });
    let error = read_error();
    assert!(
        error.contains(&format!(
            "storage at {} uses format 7; this git-remote-e2ee reads format 6",
            carrier.display()
        )),
        "{error}"
    );

    edit_carrier(&carrier, &workdir, |root| {
        fs::remove_file(root.join("FORMAT")).unwrap();
    });
    let error = read_error();
    assert!(
        error.contains("uses format 5 or earlier; this git-remote-e2ee reads format 6"),
        "{error}"
    );
}

#[test]
fn carrier_branch_fragment_selects_the_branch_through_the_helper() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let clone = temporary.path().join("clone");
    let key_path = temporary.path().join("repository.key.json");
    let source_head = init_source(&source, "vault branch marker");
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let location = format!("{}#vault", carrier.display());
    EncryptedRepository::new(GitStorage::open(&location).unwrap(), key.clone())
        .initialize("owner")
        .unwrap();

    let url = format!("e2ee::{location}");
    push_through_helper(&source, &url, &key_path, temporary.path());
    assert_success(
        helper_command(temporary.path(), temporary.path())
            .args([
                "-c",
                &format!("e2ee.key={}", key_path.display()),
                "clone",
                "-q",
                &url,
            ])
            .arg(&clone)
            .output()
            .unwrap(),
        "clone through helper",
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"], false), source_head);
    assert_eq!(git(&clone, &["config", "remote.origin.url"], false), url);

    let refs = carrier_refs(&carrier);
    let names: Vec<_> = refs
        .lines()
        .map(|line| line.split_once(' ').unwrap().0)
        .collect();
    assert_eq!(names, ["refs/heads/vault"]);
}

#[test]
fn carrier_init_refuses_an_existing_branch_and_another_branch_works() {
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
    let refs_before = carrier_refs(&carrier);

    let key = KeyFile::generate();
    let refused = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        key.clone(),
    )
    .initialize("owner")
    .unwrap_err();
    assert!(
        format!("{refused:#}").contains(&format!(
            "branch main of {remote} already exists; use an empty repository or choose another branch with e2ee::{remote}#<branch>",
            remote = carrier.display()
        )),
        "{refused:#}"
    );
    assert_eq!(carrier_refs(&carrier), refs_before);

    let location = format!("{}#vault", carrier.display());
    let encrypted = EncryptedRepository::new(GitStorage::open(&location).unwrap(), key);
    let caches = fs::read_dir(temporary.path().join("carrier-cache"))
        .unwrap()
        .filter(|entry| entry.as_ref().unwrap().path().is_dir())
        .count();
    assert_eq!(caches, 2, "each branch of one remote has its own cache");
    encrypted.initialize("owner").unwrap();
    assert!(
        encrypted
            .initialize("owner")
            .unwrap_err()
            .to_string()
            .contains("already initialized")
    );
    assert_eq!(
        git(&carrier, &["rev-parse", "refs/heads/main"], false),
        main_before
    );
    assert!(!git(&carrier, &["rev-parse", "refs/heads/vault"], false).is_empty());
}

/// Installs a pre-receive hook that rejects every push while `marker` exists,
/// removing the marker on the first rejection when `once` is set.
fn reject_pushes_while(carrier: &Path, marker: &Path, once: bool) {
    use std::os::unix::fs::PermissionsExt;
    let remove = if once {
        format!("rm '{}'", marker.display())
    } else {
        String::new()
    };
    let hook = carrier.join("hooks/pre-receive");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nif [ -e '{marker}' ]; then\n  {remove}\n  echo 'carrier test hook refused the update' >&2\n  exit 1\nfi\n",
            marker = marker.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
}

fn remote_tip(carrier: &Path) -> String {
    git(carrier, &["rev-parse", "refs/heads/main"], false)
}

#[test]
fn rejected_carrier_publish_restores_the_published_head() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let published = "5".repeat(64);
    let rejected = "6".repeat(64);
    let next = "7".repeat(64);
    let storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    storage.compare_and_swap_head(None, &published).unwrap();
    let tip = remote_tip(&carrier);

    let marker = temporary.path().join("reject");
    fs::write(&marker, "").unwrap();
    reject_pushes_while(&carrier, &marker, false);
    let error = storage
        .compare_and_swap_head(Some(&published), &rejected)
        .unwrap_err();
    assert_eq!(remote_tip(&carrier), tip);
    assert_eq!(
        storage.read_head().unwrap().as_deref(),
        Some(published.as_str())
    );
    assert!(
        error.downcast_ref::<CasConflict>().is_none(),
        "a hook rejection is not a compare-and-swap loss: {error:#}"
    );
    assert!(
        format!("{error:#}").contains("carrier test hook refused the update"),
        "the push error keeps git's stderr: {error:#}"
    );

    fs::remove_file(&marker).unwrap();
    storage
        .compare_and_swap_head(Some(&published), &next)
        .unwrap();
    assert_eq!(
        git(&carrier, &["show", "refs/heads/main:HEAD"], false),
        next
    );
    assert_eq!(
        git(&carrier, &["rev-parse", "refs/heads/main^"], false),
        tip,
        "the next publication builds on the published commit, not the rejected one"
    );
}

#[test]
fn rejected_carrier_genesis_leaves_an_uninitialized_checkout() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let marker = temporary.path().join("reject");
    fs::write(&marker, "").unwrap();
    reject_pushes_while(&carrier, &marker, true);
    let storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let rejected = "6".repeat(64);
    let next = "7".repeat(64);
    let error = storage.compare_and_swap_head(None, &rejected).unwrap_err();
    assert_eq!(storage.read_head().unwrap(), None);
    assert!(error.downcast_ref::<CasConflict>().is_none(), "{error:#}");

    storage.compare_and_swap_head(None, &next).unwrap();
    assert_eq!(
        git(&carrier, &["show", "refs/heads/main:HEAD"], false),
        next
    );
    assert_eq!(
        git(&carrier, &["rev-list", "--count", "refs/heads/main"], false),
        "1"
    );
}

#[test]
fn stale_compare_and_swap_conflicts_even_when_the_remote_head_is_garbage() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
        false,
    );
    let published = "5".repeat(64);
    GitStorage::open(carrier.to_str().unwrap())
        .unwrap()
        .compare_and_swap_head(None, &published)
        .unwrap();
    let stale = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    edit_carrier(&carrier, &temporary.path().join("editor"), |workdir| {
        fs::write(workdir.join("HEAD"), "not a manifest id\n").unwrap();
    });

    let error = stale
        .compare_and_swap_head(Some(&published), &"8".repeat(64))
        .unwrap_err();
    let conflict = error
        .downcast_ref::<CasConflict>()
        .unwrap_or_else(|| panic!("expected a conflict: {error:#}"));
    assert_eq!(conflict.actual, None);
}

#[test]
fn failed_ref_in_a_helper_push_batch_is_not_published_by_the_next_ref() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let key_path = temporary.path().join("repository.key.json");
    init_source(&source, "batch marker");
    let key = KeyFile::generate();
    key.write_new(&key_path).unwrap();
    init_carrier(temporary.path(), &carrier, &key);
    let url = format!("e2ee::{}", carrier.display());
    push_through_helper(&source, &url, &key_path, temporary.path());

    let marker = temporary.path().join("reject-once");
    fs::write(&marker, "").unwrap();
    reject_pushes_while(&carrier, &marker, true);
    let output = helper_command(&source, temporary.path())
        .args([
            "push",
            "--porcelain",
            "private",
            "main:refs/heads/a",
            "main:refs/heads/b",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stdout={stdout} stderr={stderr}");
    let status = |reference: &str| {
        stdout
            .lines()
            .find(|line| line.contains(&format!(":{reference}\t")))
            .unwrap_or_else(|| panic!("no status for {reference}: {stdout}"))
            .to_owned()
    };
    let (failed, published) = if status("refs/heads/a").starts_with('!') {
        ("refs/heads/a", "refs/heads/b")
    } else {
        ("refs/heads/b", "refs/heads/a")
    };
    assert!(status(failed).starts_with('!'), "{stdout}");
    assert!(!status(published).starts_with('!'), "{stdout}");

    let manifest =
        EncryptedRepository::new(GitStorage::open(carrier.to_str().unwrap()).unwrap(), key)
            .verify()
            .unwrap();
    let names: Vec<_> = manifest.refs.keys().map(String::as_str).collect();
    assert!(names.contains(&published), "{names:?}");
    assert!(
        !names.contains(&failed),
        "the failed ref was published by the next one: {names:?}"
    );

    assert!(
        !stdout.contains("fetch first") && !stderr.contains("fetch first"),
        "a rejected publish is not reported as a race: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("carrier test hook refused the update"),
        "{stderr}"
    );
}

#[test]
fn carrier_recovery_classifies_missing_head_manifest_as_unavailable() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    init_source(&source, "first content");
    init_source(&returning, "returning local content");

    let owner = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &owner);
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&returning, "private").unwrap();

    fs::write(source.join("note.md"), "second content\n").unwrap();
    git(&source, &["commit", "-q", "-am", "second"], false);
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let (head_id, _) = repository.current_manifest().unwrap();

    edit_carrier(
        &carrier,
        &temporary.path().join("carrier-edit"),
        |workdir| {
            fs::remove_dir_all(workdir.join("manifests").join(&head_id[..2]).join(&head_id))
                .unwrap();
        },
    );

    let recover = |publish| {
        EncryptedRepository::new(
            GitStorage::open(carrier.to_str().unwrap()).unwrap(),
            owner.clone(),
        )
        .recover(
            &returning,
            RecoveryOptions {
                publish,
                base: None,
                discard_newer: false,
                accept_stale_floor: false,
            },
        )
        .unwrap()
    };
    let report = recover(false);
    assert_eq!(
        report.classification,
        RecoveryClass::Unavailable,
        "{}",
        report.reason
    );

    let published = recover(true);
    assert_eq!(published.classification, RecoveryClass::Unavailable);
    assert!(published.published_manifest.is_none());
    assert!(published.blocked_reason.is_some());
    let carrier_head = git(&carrier, &["show", "refs/heads/main:HEAD"], false);
    assert_eq!(carrier_head, head_id);
}

#[test]
fn carrier_recovery_refuses_to_skip_a_historical_head_with_missing_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    let returning = temporary.path().join("returning");
    init_source(&source, "floor content");
    init_source(&returning, "returning local content");

    let owner = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &owner);
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&returning, "private").unwrap();
    let (floor_id, floor) = repository.current_manifest().unwrap();

    let uncommitted = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let genesis_id = floor.previous.clone().unwrap();
    let genesis_bytes = uncommitted
        .get_object(ObjectKind::Manifest, &genesis_id)
        .unwrap();
    let genesis_key =
        unwrap_generation_key(&peek_manifest_header(&genesis_bytes).unwrap(), &owner).unwrap();
    let genesis = open_manifest(&genesis_bytes, &genesis_key).unwrap();
    let policy =
        PolicyState::parse(genesis.manifest().introduced_policy.as_deref().unwrap()).unwrap();
    let newer_id =
        create_writer_successor(&uncommitted, &owner, &policy, &floor_id, floor.refs.clone());

    edit_carrier(
        &carrier,
        &temporary.path().join("carrier-edit"),
        |workdir| {
            fs::write(workdir.join("HEAD"), format!("{newer_id}\n")).unwrap();
        },
    );
    let junk_storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let junk = b"invalid successor";
    let junk_id = object_id(junk);
    junk_storage
        .put_object_if_absent(ObjectKind::Manifest, &junk_id, junk)
        .unwrap();
    junk_storage
        .compare_and_swap_head(Some(&newer_id), &junk_id)
        .unwrap();

    let report = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    )
    .recover(
        &returning,
        RecoveryOptions {
            publish: true,
            base: None,
            discard_newer: false,
            accept_stale_floor: false,
        },
    )
    .unwrap();
    assert_eq!(report.classification, RecoveryClass::Invalid);
    assert!(report.published_manifest.is_none());
    let blocked = report.blocked_reason.unwrap();
    assert!(
        blocked.contains(&format!(
            "historical carrier head {newer_id} is unavailable"
        )),
        "{blocked}"
    );
    let carrier_head = git(&carrier, &["show", "refs/heads/main:HEAD"], false);
    assert_eq!(carrier_head, junk_id);
}

#[test]
fn carrier_history_reads_skip_corrupt_copies_for_an_older_valid_one() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let source = temporary.path().join("source");
    init_source(&source, "content");

    let owner = KeyFile::generate();
    init_carrier(temporary.path(), &carrier, &owner);
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        owner.clone(),
    );
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    let (head_id, head) = repository.current_manifest().unwrap();
    let pack_id = head.new_packs[0].id.clone();
    let original = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let manifest_bytes = original.get_object(ObjectKind::Manifest, &head_id).unwrap();
    let pack_bytes = original.get_object(ObjectKind::Pack, &pack_id).unwrap();

    edit_carrier(
        &carrier,
        &temporary.path().join("carrier-edit"),
        |workdir| {
            for (directory, id) in [("manifests", &head_id), ("packs", &pack_id)] {
                let chunk = workdir
                    .join(directory)
                    .join(&id[..2])
                    .join(id)
                    .join("00000000");
                fs::write(chunk, b"corrupt copy").unwrap();
            }
        },
    );

    let storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    assert_ne!(
        storage.get_object(ObjectKind::Pack, &pack_id).unwrap(),
        pack_bytes
    );
    let history = storage
        .recovery_history(2048, 64 * 1024 * 1024)
        .unwrap()
        .unwrap();
    assert_eq!(
        history.commits[0].head_id.as_deref(),
        Some(head_id.as_str())
    );
    assert_eq!(history.manifests[&head_id], manifest_bytes);

    assert!(
        storage
            .restore_historical_object(ObjectKind::Pack, &pack_id)
            .unwrap()
    );
    assert_eq!(
        storage.get_object(ObjectKind::Pack, &pack_id).unwrap(),
        pack_bytes
    );
    assert!(
        !storage
            .restore_historical_object(ObjectKind::Pack, &"0".repeat(64))
            .unwrap()
    );
}

/// The writer joins after genesis, so the heads that predate it are sealed
/// to readers it never was. Recovery from a malformed HEAD must still work.
fn recover_junk_head_after_later_writer_push(recover_as_owner: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let _cache = isolated_cache(&temporary);
    let carrier = temporary.path().join("carrier.git");
    let owner_checkout = temporary.path().join("owner");
    let writer_checkout = temporary.path().join("writer");
    init_source(&owner_checkout, "owner content");
    init_source(&writer_checkout, "writer content");

    let owner = KeyFile::generate();
    let writer = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let admin_pin = temporary.path().join("owner.admin-state.json");
    init_carrier(temporary.path(), &carrier, &owner);
    let open = |key: &KeyFile| {
        EncryptedRepository::new(
            GitStorage::open(carrier.to_str().unwrap()).unwrap(),
            key.clone(),
        )
    };
    open(&owner).pin_admin_state(&admin_pin).unwrap();
    open(&owner)
        .add_device(
            writer.public_device().unwrap(),
            "writer",
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    open(&writer)
        .push_update_for_remote(
            &writer_checkout,
            "origin",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap();
    open(&owner).fetch_into(&owner_checkout, "origin").unwrap();
    let (floor_id, _) = open(&owner).current_manifest().unwrap();

    edit_carrier(
        &carrier,
        &temporary.path().join("carrier-edit"),
        |workdir| {
            fs::write(workdir.join("HEAD"), "junk\n").unwrap();
        },
    );

    let (key, checkout) = if recover_as_owner {
        (&owner, &owner_checkout)
    } else {
        (&writer, &writer_checkout)
    };
    let recover = |publish| {
        open(key)
            .recover(
                checkout,
                RecoveryOptions {
                    publish,
                    base: None,
                    discard_newer: false,
                    accept_stale_floor: false,
                },
            )
            .unwrap()
    };
    let report = recover(false);
    assert_eq!(report.classification, RecoveryClass::Invalid);
    assert_eq!(report.blocked_reason, None);
    assert_eq!(report.default_base.as_deref(), Some(floor_id.as_str()));
    assert_eq!(report.replays.len(), 2, "{:?}", report.replays);

    let published = recover(true);
    assert_eq!(published.blocked_reason, None);
    let recovered_id = published.published_manifest.unwrap();
    let (head, manifest) = open(key).current_manifest().unwrap();
    assert_eq!(head, recovered_id);
    assert_eq!(manifest.previous.as_deref(), Some(floor_id.as_str()));
}

#[test]
fn carrier_recovery_works_for_the_owner() {
    recover_junk_head_after_later_writer_push(true);
}

#[test]
fn carrier_recovery_works_for_a_writer_added_after_genesis() {
    recover_junk_head_after_later_writer_push(false);
}
