//! Which Git repository and configuration each `git` process sees: the
//! user's repository is the one the command names, and repositories the
//! program owns never inherit repository selection, hooks, or signing.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;

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

    let url = format!("e2ee::trusted-local:{}", carrier.display());
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

#[cfg(unix)]
#[test]
fn carrier_publication_ignores_indexed_clean_filters() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let url = format!("e2ee::trusted-local:{}", carrier.display());
    success(&sandbox.e2ee(&repo, &["init", &url]).output().unwrap());

    let attacker = sandbox.path().join("carrier-edit");
    sandbox.git(
        sandbox.path(),
        &[
            "clone",
            "-q",
            "-b",
            "main",
            carrier.to_str().unwrap(),
            attacker.to_str().unwrap(),
        ],
    );
    fs::create_dir_all(attacker.join("packs")).unwrap();
    fs::write(attacker.join("packs/.gitattributes"), "* filter=probe\n").unwrap();
    sandbox.git(&attacker, &["add", "packs/.gitattributes"]);
    sandbox.git(&attacker, &["commit", "-q", "-m", "indexed filter"]);
    sandbox.git(&attacker, &["push", "-q", "origin", "main"]);

    let marker = sandbox.path().join("filter-invoked");
    let filter = sandbox.path().join("clean-filter.sh");
    fs::write(
        &filter,
        format!("#!/bin/sh\nprintf invoked > '{}'\ncat\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&filter, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        sandbox.global_config(),
        format!(
            "[filter \"probe\"]\n\tclean = {}\n\trequired = true\n",
            filter.display()
        ),
    )
    .unwrap();

    fs::write(repo.join("note.md"), "encrypted content\n").unwrap();
    sandbox.git(&repo, &["add", "note.md"]);
    sandbox.git(&repo, &["commit", "-q", "-m", "content"]);
    sandbox.git(&repo, &["push", "-q", "origin", "main"]);
    assert!(
        !marker.exists(),
        "carrier publication ran the indexed filter"
    );
    success(&sandbox.e2ee(&repo, &["verify", "origin"]).output().unwrap());
}

#[test]
fn an_unreachable_carrier_does_not_trigger_a_cache_check() {
    let sandbox = Sandbox::new();
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let url = format!("e2ee::trusted-local:{}", carrier.display());
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
fn carrier_url_credentials_are_hidden_in_cli_errors() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let url = "e2ee::https://alice:secret@host/repo.git?access_token=token#bad branch";
    let output = sandbox.e2ee(&repo, &["init", url]).output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("https://host/[redacted]"), "{error}");
    assert!(!error.contains("secret"));
    assert!(!error.contains("token"));

    let configured = "https://alice:secret@host/repo.git?access_token=token";
    sandbox.git(&repo, &["remote", "add", "plain", configured]);
    assert_eq!(
        sandbox.git(&repo, &["config", "--get", "remote.plain.url"]),
        configured
    );
    let output = sandbox.e2ee(&repo, &["verify", "plain"]).output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("https://host/[redacted]"), "{error}");
    assert!(!error.contains("secret"));
    assert!(!error.contains("token"));
}

#[test]
fn storage_format_controls_are_escaped_in_cli_helper_and_recovery_output() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let storage = sandbox.path().join("storage");
    let url = format!("e2ee::dir:{}", storage.display());
    success(&sandbox.e2ee(&repo, &["init", &url]).output().unwrap());
    fs::write(
        storage.join("FORMAT"),
        b"git-remote-e2ee storage 8\n\r\x1b]52;c;injected\x07\n",
    )
    .unwrap();

    let verify = sandbox.e2ee(&repo, &["verify", "origin"]).output().unwrap();
    assert!(!verify.status.success());
    let verify_error = String::from_utf8(verify.stderr).unwrap();
    assert!(
        verify_error.contains("format 8\\n\\r\\u{1b}"),
        "{verify_error}"
    );
    assert!(!verify_error.contains(['\x1b', '\x07', '\r']));
    assert_eq!(verify_error.lines().count(), 1);

    let fetch = sandbox
        .command("git", &repo)
        .args(["fetch", "origin"])
        .output()
        .unwrap();
    assert!(!fetch.status.success());
    let helper_error = String::from_utf8(fetch.stderr).unwrap();
    assert!(
        helper_error.contains("format 8\\n\\r\\u{1b}"),
        "{helper_error}"
    );
    assert!(!helper_error.contains(['\x1b', '\x07', '\r']));

    let recover = sandbox
        .e2ee(&repo, &["recover", "origin"])
        .output()
        .unwrap();
    assert!(recover.status.success());
    let report = String::from_utf8(recover.stdout).unwrap();
    assert!(report.contains("format 8\\n\\r\\u{1b}"), "{report}");
    assert!(!report.contains(['\x1b', '\x07', '\r']));
    assert!(report.lines().count() > 1);
    assert_eq!(
        report
            .lines()
            .filter(|line| line.contains("injected"))
            .count(),
        1
    );
}

#[test]
fn init_escapes_controls_in_a_directory_storage_path() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let storage = sandbox.path().join("store\u{1b}[31m");
    let url = format!("e2ee::dir:{}", storage.display());
    let output = sandbox.e2ee(&repo, &["init", &url]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("store\\u{1b}[31m"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'));
}

#[test]
fn scp_carrier_failure_does_not_repeat_a_private_path_from_git() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let remote = "alice@host:private-token/repo.git";
    let ssh = "sh -c 'git upload-pack private-token/repo.git' --";
    let raw = sandbox
        .command("git", &repo)
        .args(["ls-remote", remote])
        .env("GIT_SSH_COMMAND", ssh)
        .output()
        .unwrap();
    assert!(!raw.status.success());
    assert!(String::from_utf8_lossy(&raw.stderr).contains("private-token"));

    let output = sandbox
        .e2ee(&repo, &["init", "e2ee::alice@host:private-token/repo.git"])
        .env("GIT_SSH_COMMAND", ssh)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("git fetch carrier branch failed"), "{error}");
    assert!(!error.contains("private-token"), "{error}");
}

#[test]
fn carrier_transport_rejects_an_injected_local_rewrite_even_with_file_allowed() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let key = sandbox.path().join("owner.key.json");
    let key_arg = key.to_string_lossy().into_owned();
    let real_url = format!("e2ee::trusted-local:{}", carrier.display());
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
    let attempted = sandbox
        .command("git", &repo)
        .env("GIT_ALLOW_PROTOCOL", "e2ee:file:ssh")
        .args([
            "-c",
            &rewrite,
            "-c",
            &hooks_path,
            "push",
            "-q",
            "--no-verify",
            "private",
            "main",
        ])
        .output()
        .unwrap();
    assert!(!attempted.status.success());
    assert!(String::from_utf8_lossy(&attempted.stderr).contains("git fetch carrier branch failed"));
    let tip = sandbox.git(&carrier, &["rev-parse", "refs/heads/main"]);
    let history = sandbox.git(&carrier, &["rev-list", "--count", &tip]);
    assert_eq!(
        history, "1",
        "a rewritten local receiver must not see the attempted push"
    );
}

#[cfg(unix)]
#[test]
fn trusted_local_transport_cannot_be_redirected_to_another_hook_receiver() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "trusted.git"]);
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "untrusted.git"]);
    let trusted = sandbox.path().join("trusted.git");
    let untrusted = sandbox.path().join("untrusted.git");
    let marker = sandbox.path().join("wrong-receiver-ran");
    let hook = untrusted.join("hooks/post-receive");
    fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();

    let template = sandbox.path().join("malicious-template");
    fs::create_dir(&template).unwrap();
    fs::write(
        template.join("config"),
        format!(
            "[url \"{}\"]\n\tinsteadOf = {}\n",
            untrusted.display(),
            trusted.display()
        ),
    )
    .unwrap();

    let repo = sandbox.repository("notes");
    let url = format!("e2ee::trusted-local:{}", trusted.display());
    success(
        &sandbox
            .e2ee(&repo, &["init", &url])
            .env("GIT_TEMPLATE_DIR", &template)
            .output()
            .unwrap(),
    );
    assert!(!marker.exists(), "a Git template redirected initialization");

    fs::write(
        sandbox.global_config(),
        format!(
            "[url \"e2ee::trusted-local:{}\"]\n\tinsteadOf = e2ee::trusted-local:{}\n",
            untrusted.display(),
            trusted.display()
        ),
    )
    .unwrap();
    assert_eq!(
        sandbox.git(&repo, &["remote", "get-url", "origin"]),
        format!("e2ee::trusted-local:{}", untrusted.display())
    );
    let rewritten = sandbox
        .command("git", &repo)
        .args(["push", "-q", "origin", "main"])
        .output()
        .unwrap();
    assert!(!rewritten.status.success());
    assert!(String::from_utf8_lossy(&rewritten.stderr).contains("rewritten"));
    assert!(
        !marker.exists(),
        "global URL rewrite reached another receiver"
    );

    fs::write(sandbox.global_config(), "").unwrap();
    sandbox.git(&repo, &["push", "-q", "origin", "main"]);
    let owner = KeyFile::read(Path::new(&sandbox.only_key())).unwrap();
    let new_device = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let public = new_device.public_device().unwrap();
    let public_path = sandbox.path().join("new-device.public.json");
    public.write_new(&public_path).unwrap();
    success(
        &sandbox
            .e2ee(
                &repo,
                &[
                    "device-add",
                    "origin",
                    public_path.to_str().unwrap(),
                    "--expected-device-id",
                    &public.device_id,
                    "--role",
                    "read",
                    "--label",
                    "reader",
                ],
            )
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "remote.origin.pushurl")
            .env("GIT_CONFIG_VALUE_0", &untrusted)
            .output()
            .unwrap(),
    );
    assert!(
        !marker.exists(),
        "injected pushurl reached another receiver"
    );
    assert_eq!(
        sandbox.git(&trusted, &["rev-list", "--count", "refs/heads/main"]),
        "3",
        "the trusted carrier should hold genesis, the Git push, and device-add"
    );
}

#[cfg(unix)]
#[test]
fn carrier_transport_never_runs_ext_commands() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let key_path = sandbox.path().join("owner.key.json");
    KeyFile::generate().write_new(&key_path).unwrap();
    let key_arg = key_path.to_string_lossy().into_owned();
    let marker = sandbox.path().join("ext-helper-ran");
    let helper = sandbox.path().join("ext-helper");
    fs::write(
        &helper,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    let ext = format!("ext::{}", helper.display());

    for (variable, value) in [
        ("GIT_ALLOW_PROTOCOL", "ext:ssh:https"),
        ("GIT_CONFIG_COUNT", "1"),
    ] {
        let mut command = sandbox.e2ee(
            sandbox.path(),
            &["verify", &format!("e2ee::{ext}"), "--key", &key_arg],
        );
        command.env(variable, value);
        if variable == "GIT_CONFIG_COUNT" {
            command
                .env("GIT_CONFIG_KEY_0", "protocol.ext.allow")
                .env("GIT_CONFIG_VALUE_0", "always");
        }
        let refused = command.output().unwrap();
        assert!(!refused.status.success());
        assert!(!marker.exists(), "direct ext carrier ran its helper");
    }

    let custom = sandbox.path().join("git-remote-foo");
    fs::copy(&helper, &custom).unwrap();
    fs::set_permissions(&custom, fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![sandbox.path().to_path_buf()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    let refused = sandbox
        .e2ee(
            sandbox.path(),
            &[
                "verify",
                "e2ee::foo://example.invalid/repo",
                "--key",
                &key_arg,
            ],
        )
        .env("PATH", env::join_paths(paths).unwrap())
        .env("GIT_ALLOW_PROTOCOL", "foo")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!marker.exists(), "custom URL scheme ran its helper");

    let safe_url = "ssh://example.invalid/encrypted.git";
    fs::write(
        sandbox.global_config(),
        format!("[url \"{ext}\"]\n\tinsteadOf = {safe_url}\n"),
    )
    .unwrap();
    let repo = sandbox.repository("notes");
    sandbox.git(&repo, &["remote", "add", "carrier", safe_url]);
    assert_eq!(sandbox.git(&repo, &["remote", "get-url", "carrier"]), ext);
    let refused = sandbox
        .e2ee(
            sandbox.path(),
            &["verify", &format!("e2ee::{safe_url}"), "--key", &key_arg],
        )
        .env("GIT_ALLOW_PROTOCOL", "ext:ssh")
        .env("GIT_SSH_COMMAND", "false")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!marker.exists(), "rewritten ext carrier ran its helper");

    let refused = sandbox
        .e2ee(
            sandbox.path(),
            &["verify", &format!("e2ee::{safe_url}"), "--key", &key_arg],
        )
        .env_remove("GIT_ALLOW_PROTOCOL")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "protocol.ext.allow")
        .env("GIT_CONFIG_VALUE_0", "always")
        .env("GIT_SSH_COMMAND", "false")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!marker.exists(), "injected ext permission ran its helper");

    fs::write(sandbox.global_config(), "").unwrap();
    let ssh_marker = sandbox.path().join("ssh-transport-ran");
    let ssh = sandbox.path().join("fake-ssh");
    fs::write(
        &ssh,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", ssh_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
    let refused = sandbox
        .e2ee(
            sandbox.path(),
            &["verify", &format!("e2ee::{safe_url}"), "--key", &key_arg],
        )
        .env("GIT_ALLOW_PROTOCOL", "ext:ssh")
        .env("GIT_SSH_COMMAND", &ssh)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(ssh_marker.exists(), "safe SSH transport was blocked");

    fs::remove_file(&ssh_marker).unwrap();
    fs::write(
        sandbox.global_config(),
        "[protocol \"ssh\"]\n\tallow = never\n",
    )
    .unwrap();
    let refused = sandbox
        .e2ee(
            sandbox.path(),
            &["verify", &format!("e2ee::{safe_url}"), "--key", &key_arg],
        )
        .env_remove("GIT_ALLOW_PROTOCOL")
        .env("GIT_SSH_COMMAND", &ssh)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!ssh_marker.exists(), "explicit SSH denial was overridden");
}
