use std::path::Path;
use std::process::{Command, Output};

use git_remote_e2ee::crypto::KeyFile;

fn run_cli(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_git-e2ee"))
        .args(args)
        .output()
        .unwrap()
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn add_device_args(storage: &Path, key: &Path, public: &Path) -> Vec<String> {
    vec![
        "device-add".to_owned(),
        "--storage".to_owned(),
        path_arg(storage),
        "--key".to_owned(),
        path_arg(key),
        "--device".to_owned(),
        path_arg(public),
    ]
}

#[test]
fn device_add_parses_roles_and_device_list_uses_role_names() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = temporary.path().join("storage");
    let owner_path = temporary.path().join("owner.key.json");
    let owner = KeyFile::generate();
    owner.write_new(&owner_path).unwrap();

    let initialized = run_cli(&[
        "init".to_owned(),
        "--storage".to_owned(),
        path_arg(&storage),
        "--key".to_owned(),
        path_arg(&owner_path),
    ]);
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
        let added = run_cli(&args);
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
    let legacy = run_cli(&legacy_args);
    assert!(!legacy.status.success());
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("--admin"));

    let listed = run_cli(&[
        "device-list".to_owned(),
        "--storage".to_owned(),
        path_arg(&storage),
        "--key".to_owned(),
        path_arg(&owner_path),
    ]);
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
