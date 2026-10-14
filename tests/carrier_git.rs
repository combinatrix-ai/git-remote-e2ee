use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{CasConflict, GitStorage, Storage};

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

    let updated = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let after_push = reachable_object_count(&cache);
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
