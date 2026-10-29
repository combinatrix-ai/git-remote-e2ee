use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;

struct Machine {
    root: tempfile::TempDir,
}

impl Machine {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn command(&self, program: &str, cwd: &Path, args: &[&str]) -> Output {
        let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
        let mut paths = vec![helper.parent().unwrap().to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        Command::new(program)
            .current_dir(cwd)
            .args(args)
            .env("PATH", env::join_paths(paths).unwrap())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("GIT_REMOTE_E2EE_CACHE_DIR", self.path("cache"))
            .output()
            .unwrap()
    }

    fn cli(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_git-e2ee"), cwd, args)
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command("git", cwd, args)
    }
}

fn succeed(action: &str, output: Output) -> String {
    assert!(
        output.status.success(),
        "{action} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn commit(machine: &Machine, repo: &Path, text: &str) {
    fs::write(repo.join("note.md"), text).unwrap();
    succeed("git add", machine.git(repo, &["add", "note.md"]));
    succeed(
        "git commit",
        machine.git(repo, &["commit", "-q", "-m", text]),
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    let copied = Command::new("cp")
        .arg("-R")
        .arg(source)
        .arg(destination)
        .status()
        .unwrap();
    assert!(copied.success());
}

/// A device-revoke on this machine must protect every later push from this
/// machine, even from a checkout that never fetched the revocation. Before
/// one machine floor existed, the checkout pin still accepted the replayed
/// pre-revocation storage and the push re-published content to the revoked
/// reader.
#[test]
fn push_after_rollback_of_a_revocation_seen_only_by_device_revoke_is_rejected() {
    let machine = Machine::new();
    let clone = machine.path("clone");
    let storage = machine.path("storage");
    let snapshot = machine.path("snapshot");
    fs::create_dir_all(&clone).unwrap();
    succeed(
        "git init",
        machine.git(&clone, &["init", "-q", "-b", "main"]),
    );
    succeed("config", machine.git(&clone, &["config", "user.name", "T"]));
    succeed(
        "config",
        machine.git(&clone, &["config", "user.email", "t@example.invalid"]),
    );
    let owner_path = machine.path("owner.key.json");
    let url = format!("e2ee::dir:{}", storage.display());
    succeed(
        "git-e2ee init",
        machine.cli(
            &clone,
            &["init", &url, "--key", owner_path.to_str().unwrap()],
        ),
    );
    commit(&machine, &clone, "v1");
    succeed(
        "push v1",
        machine.git(&clone, &["push", "-q", "origin", "main"]),
    );

    let owner = KeyFile::read(&owner_path).unwrap();
    let reader = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let reader_public = machine.path("reader.public.json");
    reader
        .public_device()
        .unwrap()
        .write_new(&reader_public)
        .unwrap();
    succeed(
        "device-add",
        machine.cli(
            &clone,
            &[
                "device-add",
                "origin",
                reader_public.to_str().unwrap(),
                "--label",
                "reader",
                "--role",
                "read",
            ],
        ),
    );
    succeed("fetch after add", machine.git(&clone, &["fetch", "origin"]));

    copy_tree(&storage, &snapshot);
    succeed(
        "device-revoke",
        machine.cli(
            &clone,
            &["device-revoke", "origin", &reader.device_id().unwrap()],
        ),
    );
    fs::remove_dir_all(&storage).unwrap();
    fs::rename(&snapshot, &storage).unwrap();
    let replayed_head = fs::read(storage.join("HEAD")).unwrap();

    commit(&machine, &clone, "post-revocation secret");
    let pushed = machine.git(&clone, &["push", "origin", "main"]);
    let stderr = String::from_utf8_lossy(&pushed.stderr);
    assert!(
        !pushed.status.success(),
        "push over the replayed pre-revocation state succeeded: {stderr}"
    );
    assert!(stderr.contains("rolled back"), "{stderr}");
    assert_eq!(
        fs::read(storage.join("HEAD")).unwrap(),
        replayed_head,
        "the rejected push must not publish a generation"
    );
}
