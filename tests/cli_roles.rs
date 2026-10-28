use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;

fn run_cli(state_home: &Path, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_git-e2ee"))
        .current_dir(state_home)
        .env("XDG_STATE_HOME", state_home.join("state"))
        .env("XDG_CONFIG_HOME", state_home.join("config"))
        .env("GIT_REMOTE_E2EE_CACHE_DIR", state_home.join("cache"))
        .args(args)
        .output()
        .unwrap()
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn dir_url(storage: &Path) -> String {
    format!("e2ee::dir:{}", storage.display())
}

fn add_device_args(storage: &Path, key: &Path, public: &Path, label: &str) -> Vec<String> {
    vec![
        "device-add".to_owned(),
        dir_url(storage),
        path_arg(public),
        "--label".to_owned(),
        label.to_owned(),
        "--key".to_owned(),
        path_arg(key),
    ]
}

#[test]
fn device_add_parses_roles_and_device_list_uses_role_names() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = temporary.path().join("storage");
    let owner_path = temporary.path().join("owner.key.json");
    let owner = KeyFile::generate();
    owner.write_new(&owner_path).unwrap();

    let initialized = run_cli(
        temporary.path(),
        &[
            "init".to_owned(),
            dir_url(&storage),
            "--key".to_owned(),
            path_arg(&owner_path),
        ],
    );
    assert!(
        initialized.status.success(),
        "git-e2ee init: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let roles = [
        ("default", None, "write"),
        ("reader", Some("read"), "read"),
        ("writer", Some("write"), "write"),
        ("admin", Some("admin"), "admin"),
    ];
    let mut device_ids = Vec::new();
    for (name, selected_role, expected_role) in roles {
        let device_key = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let public = device_key.public_device().unwrap();
        let public_path = temporary.path().join(format!("{name}.public.json"));
        public.write_new(&public_path).unwrap();
        let mut args = add_device_args(&storage, &owner_path, &public_path, name);
        if let Some(role) = selected_role {
            args.extend(["--role".to_owned(), role.to_owned()]);
        }
        let added = run_cli(temporary.path(), &args);
        assert!(
            added.status.success(),
            "git-e2ee device-add {name}: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        device_ids.push((public.device_id, name, expected_role));
    }

    let mut legacy_args = add_device_args(
        &storage,
        &owner_path,
        &temporary.path().join("default.public.json"),
        "legacy",
    );
    legacy_args.push("--admin".to_owned());
    let legacy = run_cli(temporary.path(), &legacy_args);
    assert!(!legacy.status.success());
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("--admin"));

    let listed = run_cli(
        temporary.path(),
        &[
            "device-list".to_owned(),
            dir_url(&storage),
            "--key".to_owned(),
            path_arg(&owner_path),
        ],
    );
    assert!(
        listed.status.success(),
        "git-e2ee device-list: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let output = String::from_utf8(listed.stdout).unwrap();
    for (device_id, name, role) in device_ids {
        assert!(
            output.contains(&format!("{device_id}  {name}  role={role}  status=active")),
            "missing role {role} for {device_id} in:\n{output}"
        );
    }
    let owner_id = owner.device_id().unwrap();
    assert!(output.contains(&format!("* {owner_id}  ")));
}

#[test]
fn init_accepts_relative_storage_and_key_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let owner = KeyFile::generate();
    owner
        .write_new(&temporary.path().join("owner.key.json"))
        .unwrap();

    let initialized = Command::new(env!("CARGO_BIN_EXE_git-e2ee"))
        .current_dir(temporary.path())
        .env("XDG_STATE_HOME", temporary.path().join("state"))
        .args(["init", "e2ee::dir:storage", "--key", "owner.key.json"])
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "git-e2ee init: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert!(
        temporary
            .path()
            .join("state/git-e2ee")
            .join(&owner.repository_root)
            .join("admin-state.json")
            .is_file(),
        "init must pin the administrator state under XDG_STATE_HOME"
    );
}

#[test]
fn admin_pin_survives_moving_the_key() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = temporary.path().join("storage");
    let snapshot = temporary.path().join("storage-snapshot");
    let owner_path = temporary.path().join("owner.key.json");
    let moved_path = temporary.path().join("moved.key.json");
    let owner = KeyFile::generate();
    owner.write_new(&owner_path).unwrap();
    let device_public = |name: &str| {
        let key = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
        let path = temporary.path().join(format!("{name}.public.json"));
        key.public_device().unwrap().write_new(&path).unwrap();
        path
    };
    let first = device_public("first");
    let second = device_public("second");

    let initialized = run_cli(
        temporary.path(),
        &[
            "init".to_owned(),
            dir_url(&storage),
            "--key".to_owned(),
            path_arg(&owner_path),
        ],
    );
    assert!(initialized.status.success());
    let copied = Command::new("cp")
        .arg("-R")
        .arg(&storage)
        .arg(&snapshot)
        .status()
        .unwrap();
    assert!(copied.success());
    let added = run_cli(
        temporary.path(),
        &add_device_args(&storage, &owner_path, &first, "first"),
    );
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    fs::remove_dir_all(&storage).unwrap();
    fs::rename(&snapshot, &storage).unwrap();
    fs::rename(&owner_path, &moved_path).unwrap();
    let rolled_back = run_cli(
        temporary.path(),
        &add_device_args(&storage, &moved_path, &second, "second"),
    );
    assert!(!rolled_back.status.success());
    let stderr = String::from_utf8_lossy(&rolled_back.stderr);
    assert!(stderr.contains("rolled back"), "{stderr}");
}

struct Fixture {
    root: tempfile::TempDir,
    storage: std::path::PathBuf,
    owner_path: std::path::PathBuf,
    owner: KeyFile,
}

impl Fixture {
    fn initialized(label: Option<&str>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let storage = root.path().join("storage");
        let owner_path = root.path().join("owner.key.json");
        let owner = KeyFile::generate();
        owner.write_new(&owner_path).unwrap();
        let fixture = Self {
            root,
            storage,
            owner_path,
            owner,
        };
        let mut args = vec![
            "init".to_owned(),
            dir_url(&fixture.storage),
            "--key".to_owned(),
            path_arg(&fixture.owner_path),
        ];
        if let Some(label) = label {
            args.extend(["--label".to_owned(), label.to_owned()]);
        }
        fixture.succeed(&args);
        fixture
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn run(&self, args: &[String]) -> Output {
        run_cli(self.path(), args)
    }

    fn succeed(&self, args: &[String]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "git-e2ee {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn new_device(&self, name: &str) -> (String, std::path::PathBuf) {
        let key = KeyFile::generate_for_repository(self.owner.repository_root.clone()).unwrap();
        let public = key.public_device().unwrap();
        let path = self.path().join(format!("{name}.public.json"));
        public.write_new(&path).unwrap();
        let private = self.path().join(format!("{name}.key.json"));
        if !private.exists() {
            key.write_new(&private).unwrap();
        }
        (public.device_id, path)
    }

    fn add(&self, public: &Path, label: &str) -> Output {
        self.run(&add_device_args(
            &self.storage,
            &self.owner_path,
            public,
            label,
        ))
    }

    fn list(&self) -> Output {
        self.list_as(&self.owner_path)
    }

    fn list_as(&self, key: &Path) -> Output {
        self.run(&[
            "device-list".to_owned(),
            dir_url(&self.storage),
            "--key".to_owned(),
            path_arg(key),
        ])
    }

    fn generation(&self) -> String {
        self.succeed(&[
            "verify".to_owned(),
            dir_url(&self.storage),
            "--key".to_owned(),
            path_arg(&self.owner_path),
        ])
        .split(" (")
        .next()
        .unwrap()
        .to_owned()
    }
}

#[test]
fn device_list_shows_labels_next_to_full_ids_and_marks_the_current_key() {
    let fixture = Fixture::initialized(Some("laptop"));
    let (stannum_id, stannum) = fixture.new_device("stannum");
    let (phone_id, phone) = fixture.new_device("phone");
    assert!(fixture.add(&stannum, "stannum").status.success());
    let added = fixture.add(&phone, "phone");
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let listed = fixture.list();
    assert!(listed.status.success());
    let output = String::from_utf8(listed.stdout).unwrap();
    let owner_id = fixture.owner.device_id().unwrap();
    let mut lines: Vec<&str> = output.lines().collect();
    lines.sort();
    let mut expected = vec![
        format!("* {owner_id}  laptop  role=admin  status=active"),
        format!("  {stannum_id}  stannum  role=write  status=active"),
        format!("  {phone_id}  phone  role=write  status=active"),
    ];
    expected.sort();
    assert_eq!(lines, expected, "{output}");
}

#[test]
fn device_add_rejects_invalid_and_duplicate_labels_without_publishing() {
    let fixture = Fixture::initialized(Some("laptop"));
    let (_, existing) = fixture.new_device("existing");
    assert!(fixture.add(&existing, "stannum").status.success());
    let before = fixture.generation();

    let too_long = "a".repeat(65);
    for label in [
        "",
        too_long.as_str(),
        " stannum2",
        "stannum2 ",
        "evil\u{202E}txt",
        "zero\u{200B}width",
        "two\nlines",
        "stannum",
        "laptop",
    ] {
        let (_, public) = fixture.new_device("candidate");
        let output = fixture.add(&public, label);
        assert!(!output.status.success(), "accepted label {label:?}");
        assert_eq!(fixture.generation(), before, "label {label:?} published");
        fs::remove_file(public).unwrap();
    }

    let (_, longest) = fixture.new_device("longest");
    assert!(fixture.add(&longest, &"a".repeat(64)).status.success());
}

#[test]
fn a_revoked_device_label_can_be_reused() {
    let fixture = Fixture::initialized(Some("laptop"));
    let (old_id, old) = fixture.new_device("old");
    assert!(fixture.add(&old, "phone").status.success());
    fixture.succeed(&[
        "device-revoke".to_owned(),
        dir_url(&fixture.storage),
        old_id.clone(),
        "--key".to_owned(),
        path_arg(&fixture.owner_path),
    ]);
    let (new_id, new) = fixture.new_device("new");
    let reused = fixture.add(&new, "phone");
    assert!(
        reused.status.success(),
        "{}",
        String::from_utf8_lossy(&reused.stderr)
    );
    let output = String::from_utf8(fixture.list().stdout).unwrap();
    assert!(output.contains(&format!("  {old_id}  phone  role=write  status=revoked")));
    assert!(output.contains(&format!("  {new_id}  phone  role=write  status=active")));
}

#[test]
fn device_list_refuses_a_rolled_back_membership() {
    let fixture = Fixture::initialized(Some("laptop"));
    let snapshot = fixture.path().join("storage-snapshot");
    let copied = Command::new("cp")
        .arg("-R")
        .arg(&fixture.storage)
        .arg(&snapshot)
        .status()
        .unwrap();
    assert!(copied.success());
    let (_, phone) = fixture.new_device("phone");
    assert!(fixture.add(&phone, "phone").status.success());
    assert!(fixture.list().status.success());

    fs::remove_dir_all(&fixture.storage).unwrap();
    fs::rename(&snapshot, &fixture.storage).unwrap();
    let listed = fixture.list();
    assert!(!listed.status.success());
    let stderr = String::from_utf8_lossy(&listed.stderr);
    assert!(stderr.contains("rolled back"), "{stderr}");
}

#[test]
fn init_without_a_label_gives_the_owner_one() {
    let fixture = Fixture::initialized(None);
    let output = String::from_utf8(fixture.list().stdout).unwrap();
    let owner_id = fixture.owner.device_id().unwrap();
    let line = output
        .lines()
        .find(|line| line.starts_with(&format!("* {owner_id}  ")))
        .unwrap_or_else(|| panic!("owner line missing: {output}"));
    let label = line.split("  ").nth(1).unwrap();
    assert!(!label.is_empty() && !label.starts_with("role="), "{line}");
}
