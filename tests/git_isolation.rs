//! Which Git repository and configuration each `git` process sees: the
//! user's repository is the one the command names, and repositories the
//! program owns never inherit repository selection, hooks, or signing.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self {
            root: tempfile::tempdir().unwrap(),
        };
        fs::write(sandbox.global_config(), "").unwrap();
        sandbox
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn global_config(&self) -> PathBuf {
        self.path().join("gitconfig")
    }

    fn command(&self, program: &str, workdir: &Path) -> Command {
        let helper = Path::new(env!("CARGO_BIN_EXE_git-remote-e2ee"));
        let mut paths = vec![helper.parent().unwrap().to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        let mut command = Command::new(program);
        command
            .current_dir(workdir)
            .env("PATH", env::join_paths(paths).unwrap())
            .env("XDG_CONFIG_HOME", self.path().join("config"))
            .env("XDG_STATE_HOME", self.path().join("state"))
            .env("GIT_REMOTE_E2EE_CACHE_DIR", self.path().join("cache"))
            .env("GIT_CONFIG_GLOBAL", self.global_config())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "E2EE Test")
            .env("GIT_AUTHOR_EMAIL", "git-remote-e2ee@example.invalid")
            .env("GIT_COMMITTER_NAME", "E2EE Test")
            .env("GIT_COMMITTER_EMAIL", "git-remote-e2ee@example.invalid");
        for variable in ["GIT_DIR", "GIT_WORK_TREE", "GIT_TRACE"] {
            command.env_remove(variable);
        }
        command
    }

    fn e2ee(&self, workdir: &Path, args: &[&str]) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_git-e2ee"), workdir);
        command.args(args);
        command
    }

    fn git(&self, workdir: &Path, args: &[&str]) -> String {
        success(&self.command("git", workdir).args(args).output().unwrap())
    }

    fn repository(&self, name: &str) -> PathBuf {
        let repo = self.path().join(name);
        fs::create_dir_all(&repo).unwrap();
        self.git(&repo, &["init", "-q", "-b", "main"]);
        self.git(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
        repo
    }

    fn only_key(&self) -> String {
        let keys: Vec<_> = fs::read_dir(self.path().join("config/git-e2ee/keys"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(keys.len(), 1);
        keys[0].to_string_lossy().into_owned()
    }

    /// A repository whose `origin` is directory storage holding one pushed
    /// commit, and whose storage HEAD was then replaced with garbage.
    fn repository_with_invalid_storage_head(&self) -> (PathBuf, PathBuf) {
        let repo = self.repository("notes");
        let storage = self.path().join("storage");
        let url = format!("e2ee::dir:{}", storage.display());
        success(&self.e2ee(&repo, &["init", &url]).output().unwrap());
        self.git(&repo, &["push", "-q", "origin", "main"]);
        fs::write(storage.join("HEAD"), "not a manifest id\n").unwrap();
        (repo, storage)
    }
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .trim()
        .to_owned()
}

fn object_files(git_dir: &Path) -> Vec<PathBuf> {
    fn walk(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, files);
            } else {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&git_dir.join("objects"), &mut files);
    files
}

#[test]
fn recovery_scratch_repository_ignores_an_inherited_git_dir() {
    let sandbox = Sandbox::new();
    let (repo, storage) = sandbox.repository_with_invalid_storage_head();
    let bystander = sandbox.path().join("bystander");
    sandbox.git(sandbox.path(), &["init", "-q", "bystander"]);
    let bystander_git = bystander.join(".git");
    let before = object_files(&bystander_git);

    let url = format!("e2ee::dir:{}", storage.display());
    let key = sandbox.only_key();
    let report = success(
        &sandbox
            .e2ee(
                sandbox.path(),
                &[
                    "recover",
                    &url,
                    "--key",
                    &key,
                    "--repo",
                    &repo.to_string_lossy(),
                    "--publish",
                    "--accept-stale-floor",
                ],
            )
            .env("GIT_DIR", &bystander_git)
            .output()
            .unwrap(),
    );
    assert!(report.contains("published recovery manifest"), "{report}");
    assert_eq!(
        object_files(&bystander_git),
        before,
        "recovery wrote into the repository GIT_DIR named"
    );
    assert!(!bystander_git.join("git-remote-e2ee").exists());
    assert!(repo.join(".git/git-remote-e2ee").is_dir());
}

#[test]
fn recover_resolves_its_target_through_the_named_repository() {
    let sandbox = Sandbox::new();
    let (repo, _) = sandbox.repository_with_invalid_storage_head();
    let other = sandbox.repository("other");
    let outside = sandbox.path().join("outside");
    fs::create_dir(&outside).unwrap();

    for workdir in [&other, &outside] {
        let report = success(
            &sandbox
                .e2ee(
                    workdir,
                    &["recover", "origin", "--repo", &repo.to_string_lossy()],
                )
                .output()
                .unwrap(),
        );
        assert!(report.contains("storage head: invalid"), "{report}");
    }
    assert!(
        repo.join(".git/git-remote-e2ee").is_dir(),
        "recovery state belongs to the named repository"
    );
    assert!(!other.join(".git/git-remote-e2ee").exists());
}

#[cfg(unix)]
#[test]
fn carrier_publication_ignores_user_hooks_and_signing() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);

    let failing = |path: &Path| {
        fs::write(path, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    };
    let hooks = sandbox.path().join("hooks");
    fs::create_dir(&hooks).unwrap();
    for hook in ["pre-commit", "commit-msg", "post-commit", "pre-push"] {
        failing(&hooks.join(hook));
    }
    let gpg = sandbox.path().join("failing-gpg");
    failing(&gpg);
    fs::write(
        sandbox.global_config(),
        format!(
            "[commit]\n\tgpgSign = true\n[tag]\n\tgpgSign = true\n[gpg]\n\tprogram = {}\n[core]\n\thooksPath = {}\n",
            gpg.display(),
            hooks.display()
        ),
    )
    .unwrap();

    let url = format!("e2ee::{}", carrier.display());
    success(&sandbox.e2ee(&repo, &["init", &url]).output().unwrap());
    sandbox.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);

    let tip = sandbox.git(&carrier, &["rev-parse", "refs/heads/main"]);
    let history = sandbox.git(&carrier, &["rev-list", "--count", &tip]);
    assert_eq!(history, "2", "genesis and one push");
    let author = sandbox.git(
        &carrier,
        &["log", "-1", "--format=%an <%ae> %cn <%ce>", &tip],
    );
    assert_eq!(
        author,
        "git-remote-e2ee <git-remote-e2ee@invalid> git-remote-e2ee <git-remote-e2ee@invalid>"
    );
    let signature = sandbox.git(&carrier, &["cat-file", "commit", &tip]);
    assert!(!signature.contains("gpgsig"), "{signature}");
}

#[test]
fn an_unreachable_carrier_does_not_trigger_a_cache_check() {
    let sandbox = Sandbox::new();
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let url = format!("e2ee::{}", carrier.display());
    success(
        &sandbox
            .e2ee(sandbox.path(), &["init", &url])
            .output()
            .unwrap(),
    );
    let key = sandbox.only_key();
    fs::rename(&carrier, sandbox.path().join("offline.git")).unwrap();

    let trace = sandbox.path().join("trace");
    let output = sandbox
        .e2ee(sandbox.path(), &["verify", &url, "--key", &key])
        .env("GIT_TRACE", &trace)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let trace = fs::read_to_string(trace).unwrap();
    assert!(trace.contains("fetch"), "{trace}");
    assert!(
        !trace.contains("fsck"),
        "an offline fetch ran a cache corruption check: {trace}"
    );
}

#[test]
fn carrier_transport_keeps_config_injected_with_dash_c_but_not_its_hooks() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let key = sandbox.path().join("owner.key.json");
    let key_arg = key.to_string_lossy().into_owned();
    let real_url = format!("e2ee::{}", carrier.display());
    success(
        &sandbox
            .e2ee(sandbox.path(), &["init", &real_url, "--key", &key_arg])
            .output()
            .unwrap(),
    );

    let hooks = sandbox.path().join("hooks");
    fs::create_dir(&hooks).unwrap();
    let pre_push = hooks.join("pre-push");
    fs::write(&pre_push, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&pre_push, fs::Permissions::from_mode(0o755)).unwrap();

    let repo = sandbox.repository("notes");
    sandbox.git(
        &repo,
        &["remote", "add", "private", "e2ee::example-carrier:notes"],
    );
    sandbox.git(&repo, &["config", "remote.private.e2ee-key", &key_arg]);
    let rewrite = format!("url.{}.insteadOf=example-carrier:notes", carrier.display());
    let hooks_path = format!("core.hooksPath={}", hooks.display());
    sandbox.git(
        &repo,
        &[
            "-c",
            &rewrite,
            "-c",
            &hooks_path,
            "push",
            "-q",
            "--no-verify",
            "private",
            "main",
        ],
    );
    let tip = sandbox.git(&carrier, &["rev-parse", "refs/heads/main"]);
    let history = sandbox.git(&carrier, &["rev-list", "--count", &tip]);
    assert_eq!(
        history, "2",
        "genesis and one push through the rewritten URL"
    );
}
