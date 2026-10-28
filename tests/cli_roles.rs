use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;

fn run_cli(state_home: &Path, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_git-e2ee"))
        .current_dir(state_home)
        .env("XDG_STATE_HOME", state_home.join("state"))
        .env("XDG_CONFIG_HOME", state_home.join("config"))
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

fn add_device_args(storage: &Path, key: &Path, public: &Path) -> Vec<String> {
    vec![
        "device-add".to_owned(),
        dir_url(storage),
        path_arg(public),
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
        let mut args = add_device_args(&storage, &owner_path, &public_path);
        if let Some(role) = selected_role {
            args.extend(["--role".to_owned(), role.to_owned()]);
        }
        let added = run_cli(temporary.path(), &args);
        assert!(
            added.status.success(),
            "git-e2ee device-add {name}: {}",
            String::from_utf8_lossy(&added.stderr)
        );
        device_ids.push((public.device_id, expected_role));
    }

    let mut legacy_args = add_device_args(
        &storage,
        &owner_path,
        &temporary.path().join("default.public.json"),
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
    for (device_id, role) in device_ids {
        assert!(
            output.contains(&format!("{device_id} role={role} status=active")),
            "missing role {role} for {device_id} in:\n{output}"
        );
    }
    let owner_id = owner.device_id().unwrap();
    assert!(output.contains(&format!("{owner_id} role=admin status=active")));
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
        &add_device_args(&storage, &owner_path, &first),
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
        &add_device_args(&storage, &moved_path, &second),
    );
    assert!(!rolled_back.status.success());
    let stderr = String::from_utf8_lossy(&rolled_back.stderr);
    assert!(stderr.contains("rolled back"), "{stderr}");
}
