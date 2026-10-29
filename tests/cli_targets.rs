use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

struct Sandbox {
    root: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.root.path()
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
            .env("GIT_AUTHOR_NAME", "E2EE Test")
            .env("GIT_AUTHOR_EMAIL", "git-remote-e2ee@example.invalid")
            .env("GIT_COMMITTER_NAME", "E2EE Test")
            .env("GIT_COMMITTER_EMAIL", "git-remote-e2ee@example.invalid");
        command
    }

    fn e2ee(&self, workdir: &Path, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_git-e2ee"), workdir)
            .args(args)
            .output()
            .unwrap()
    }

    fn git(&self, workdir: &Path, args: &[&str]) -> String {
        let output = self.command("git", workdir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn repository(&self, name: &str) -> std::path::PathBuf {
        let repo = self.path().join(name);
        fs::create_dir_all(&repo).unwrap();
        self.git(&repo, &["init", "-q", "-b", "main"]);
        self.git(&repo, &["commit", "-q", "--allow-empty", "-m", "first"]);
        repo
    }

    fn keys(&self) -> Vec<std::path::PathBuf> {
        match fs::read_dir(self.path().join("config/git-e2ee/keys")) {
            Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn init_inside_a_repository_creates_a_key_and_adds_origin() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    let storage = sandbox.path().join("storage");

    let output = success(&sandbox.e2ee(&repo, &["init", "e2ee::dir:../storage"]));
    let keys = sandbox.keys();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert!(output.contains("created key"), "{output}");
    assert!(output.contains("added remote origin"), "{output}");
    let url = sandbox.git(&repo, &["config", "--get", "remote.origin.url"]);
    assert_eq!(
        fs::canonicalize(url.strip_prefix("e2ee::dir:").unwrap()).unwrap(),
        fs::canonicalize(&storage).unwrap()
    );
    assert_eq!(
        sandbox.git(&repo, &["config", "--get", "remote.origin.e2ee-key"]),
        keys[0].to_string_lossy()
    );

    sandbox.git(&repo, &["push", "-q", "origin", "main"]);
    let verified = success(&sandbox.e2ee(&repo, &["verify", "origin"]));
    assert!(
        verified.contains("verified generation 1 (1 refs"),
        "{verified}"
    );
    let listed = success(&sandbox.e2ee(&repo, &["device-list", "origin"]));
    assert!(
        listed.starts_with("* ") && listed.contains("  role=admin  status=active"),
        "{listed}"
    );
    let label = listed.split("  ").nth(1).unwrap_or_default();
    assert!(
        !label.is_empty(),
        "init without --label must label the owner: {listed}"
    );
}

#[test]
fn init_refuses_an_existing_remote_before_creating_anything() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    sandbox.git(
        &repo,
        &["remote", "add", "origin", "https://example.invalid/x.git"],
    );

    let output = sandbox.e2ee(&repo, &["init", "e2ee::dir:../storage"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--name"), "{stderr}");
    assert!(!sandbox.path().join("storage").exists());
    assert!(sandbox.keys().is_empty());

    success(&sandbox.e2ee(
        &repo,
        &["init", "e2ee::dir:../storage", "--name", "private"],
    ));
    sandbox.git(&repo, &["push", "-q", "private", "main"]);
}

#[test]
fn failed_init_removes_the_key_it_created() {
    let sandbox = Sandbox::new();
    let url = format!("e2ee::dir:{}", sandbox.path().join("storage").display());

    success(&sandbox.e2ee(sandbox.path(), &["init", &url]));
    assert_eq!(sandbox.keys().len(), 1);

    let second = sandbox.e2ee(sandbox.path(), &["init", &url]);
    assert!(!second.status.success());
    let keys = sandbox.keys();
    assert_eq!(keys.len(), 1, "{keys:?}");
}

#[test]
fn verify_takes_a_carrier_url_outside_a_repository() {
    let sandbox = Sandbox::new();
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let key = sandbox.path().join("owner.key.json");
    let url = format!("e2ee::{}", carrier.display());
    let key_arg = key.to_string_lossy().into_owned();

    let output = success(&sandbox.e2ee(sandbox.path(), &["init", &url, "--key", &key_arg]));
    assert!(!output.contains("added remote"), "{output}");
    let verified = success(&sandbox.e2ee(sandbox.path(), &["verify", &url, "--key", &key_arg]));
    assert!(verified.contains("verified generation 0"), "{verified}");

    let missing_key = sandbox.e2ee(sandbox.path(), &["verify", &url]);
    assert!(!missing_key.status.success());
    assert!(String::from_utf8_lossy(&missing_key.stderr).contains("--key"));
}

#[test]
fn unknown_or_plain_remote_names_are_rejected() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    sandbox.git(
        &repo,
        &["remote", "add", "plain", "https://example.invalid/x.git"],
    );

    let unknown = sandbox.e2ee(&repo, &["verify", "notes"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no Git remote named notes"));

    let plain = sandbox.e2ee(&repo, &["verify", "plain"]);
    assert!(!plain.status.success());
    assert!(String::from_utf8_lossy(&plain.stderr).contains("not an e2ee:: remote"));
}

#[cfg(unix)]
fn init_with_carrier_hook(sandbox: &Sandbox, hook: &str, body: &str) -> (String, String) {
    use std::os::unix::fs::PermissionsExt;

    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let path = sandbox.path().join("carrier.git/hooks").join(hook);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let url = format!("e2ee::{}", sandbox.path().join("carrier.git").display());
    let output = sandbox.e2ee(sandbox.path(), &["init", &url]);
    assert!(!output.status.success());
    fs::remove_file(&path).unwrap();
    (url, String::from_utf8_lossy(&output.stderr).into_owned())
}

#[cfg(unix)]
#[test]
fn init_keeps_its_key_when_the_floor_fails_after_publication() {
    let sandbox = Sandbox::new();
    let state = sandbox.path().join("state/git-e2ee");
    let (url, stderr) = init_with_carrier_hook(
        &sandbox,
        "post-receive",
        &format!(
            "for root in '{}'/*/; do mkdir \"${{root}}continuity.json\"; done",
            state.display()
        ),
    );
    let keys = sandbox.keys();
    assert_eq!(
        keys.len(),
        1,
        "the published owner key was deleted: {stderr}"
    );
    assert!(
        stderr.contains(&*keys[0].to_string_lossy()),
        "error must name the kept key: {stderr}"
    );
    assert!(stderr.contains("storage is initialized"), "{stderr}");

    for root in fs::read_dir(&state).unwrap() {
        fs::remove_dir(root.unwrap().path().join("continuity.json")).unwrap();
    }
    let key = keys[0].to_string_lossy().into_owned();
    let verified = success(&sandbox.e2ee(sandbox.path(), &["verify", &url, "--key", &key]));
    assert!(verified.contains("verified generation 0"), "{verified}");
}

#[cfg(unix)]
#[test]
fn init_keeps_its_key_when_genesis_publication_reports_an_error() {
    let sandbox = Sandbox::new();
    let (_, stderr) = init_with_carrier_hook(&sandbox, "pre-receive", "exit 1");
    let keys = sandbox.keys();
    assert_eq!(keys.len(), 1, "{stderr}");
    assert!(stderr.contains(&*keys[0].to_string_lossy()), "{stderr}");
    assert!(stderr.contains("may already be initialized"), "{stderr}");
}

#[test]
fn init_refused_by_an_occupied_carrier_branch_removes_its_key() {
    let sandbox = Sandbox::new();
    let repo = sandbox.repository("notes");
    sandbox.git(sandbox.path(), &["init", "-q", "--bare", "carrier.git"]);
    let carrier = sandbox.path().join("carrier.git");
    sandbox.git(&repo, &["push", "-q", &carrier.to_string_lossy(), "main"]);
    let url = format!("e2ee::{}", carrier.display());

    let output = sandbox.e2ee(sandbox.path(), &["init", &url]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert!(sandbox.keys().is_empty(), "{stderr}");
}
