use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use base64::Engine;
use git_remote_e2ee::crypto::{KeyFile, object_id};
use git_remote_e2ee::manifest::{ManifestHeader, peek_manifest_header};
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage, Storage};

static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn filesystem_storage_hides_device_metadata_and_pads_reader_envelopes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("storage");
    run_metadata_scenario(
        || FilesystemStorage::new(&root),
        || filesystem_snapshot(&root),
        || assert!(!root.join("policies").exists()),
        temporary.path(),
    );
}

#[test]
fn carrier_history_hides_device_metadata_and_pads_reader_envelopes() {
    let temporary = tempfile::tempdir().unwrap();
    let _cache_lock = CACHE_ENV_LOCK.lock().unwrap();
    unsafe {
        env::set_var(
            "GIT_REMOTE_E2EE_CACHE_DIR",
            temporary.path().join("carrier-cache"),
        )
    };
    let carrier = temporary.path().join("carrier.git");
    let output = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&carrier)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git init --bare: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    run_metadata_scenario(
        || GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        || carrier_snapshot(&carrier),
        || {
            let paths = git_output(&carrier, &["log", "--all", "--name-only", "--format="]);
            assert!(!String::from_utf8_lossy(&paths.stdout).contains("e2ee/policies/"));
        },
        temporary.path(),
    );
}

fn run_metadata_scenario<S: Storage>(
    make_storage: impl Fn() -> S,
    snapshot: impl Fn() -> Vec<u8>,
    no_policy_objects: impl Fn(),
    scratch: &Path,
) {
    let owner = KeyFile::generate();
    let pin = scratch.join("owner.admin-state.json");
    let repository = EncryptedRepository::new(make_storage(), owner.clone());
    repository.initialize().unwrap();
    repository.pin_admin_state(&pin).unwrap();
    let mut devices = vec![owner.public_device().unwrap()];
    assert_eq!(
        stored_header(make_storage()).generation_key_envelopes.len(),
        4
    );
    assert_storage_is_anonymous(&snapshot(), &devices);
    no_policy_objects();

    let readers: Vec<_> = (0..4)
        .map(|_| KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap())
        .collect();
    for (index, reader) in readers.iter().enumerate() {
        repository
            .add_device(
                reader.public_device().unwrap(),
                DeviceRoles::collaborator(),
                &pin,
            )
            .unwrap();
        devices.push(reader.public_device().unwrap());
        let expected = if index == 3 { 8 } else { 4 };
        assert_eq!(
            stored_header(make_storage()).generation_key_envelopes.len(),
            expected
        );
        assert_storage_is_anonymous(&snapshot(), &devices);
        no_policy_objects();
    }

    repository
        .revoke_device(&readers[0].device_id().unwrap(), &pin)
        .unwrap();
    assert_eq!(
        stored_header(make_storage()).generation_key_envelopes.len(),
        4
    );
    assert_storage_is_anonymous(&snapshot(), &devices);
    no_policy_objects();
}

fn stored_header(storage: impl Storage) -> ManifestHeader {
    let head = storage.read_head().unwrap().unwrap();
    let bytes = storage
        .get_object(git_remote_e2ee::storage::ObjectKind::Manifest, &head)
        .unwrap();
    assert_eq!(object_id(&bytes), head);
    peek_manifest_header(&bytes).unwrap()
}

fn assert_storage_is_anonymous(bytes: &[u8], devices: &[git_remote_e2ee::crypto::PublicDevice]) {
    let mut tokens = vec![
        b"reader".to_vec(),
        b"writer".to_vec(),
        b"administrator".to_vec(),
        b"signing_public_key".to_vec(),
        b"wrapping_public_key".to_vec(),
        b"device_id".to_vec(),
        b"policies/".to_vec(),
    ];
    for device in devices {
        tokens.push(device.device_id.as_bytes().to_vec());
        tokens.push(hex::decode(&device.device_id).unwrap());
        tokens.push(device.signing_public_key.as_bytes().to_vec());
        tokens.push(
            base64::engine::general_purpose::STANDARD
                .decode(&device.signing_public_key)
                .unwrap(),
        );
        tokens.push(device.wrapping_public_key.as_bytes().to_vec());
        tokens.push(
            base64::engine::general_purpose::STANDARD
                .decode(&device.wrapping_public_key)
                .unwrap(),
        );
    }
    for token in tokens {
        assert!(
            !bytes.windows(token.len()).any(|window| window == token),
            "storage contains plaintext metadata token {:?}",
            String::from_utf8_lossy(&token)
        );
    }
}

fn filesystem_snapshot(root: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_files(root, root, &mut bytes);
    bytes
}

fn carrier_snapshot(root: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_files(root, root, &mut bytes);

    let reachable = git_output(root, &["rev-list", "--objects", "--all"]);
    assert!(
        reachable.status.success(),
        "git rev-list: {}",
        String::from_utf8_lossy(&reachable.stderr)
    );
    let ids = String::from_utf8(reachable.stdout).unwrap();
    let mut child = Command::new("git")
        .arg(format!("--git-dir={}", root.display()))
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in ids.lines() {
            let id = line.split_whitespace().next().unwrap();
            writeln!(stdin, "{id}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "git cat-file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    bytes.extend_from_slice(&output.stdout);
    bytes
}

fn append_files(root: &Path, directory: &Path, bytes: &mut Vec<u8>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).unwrap();
        bytes.extend_from_slice(relative.to_string_lossy().as_bytes());
        if entry.file_type().unwrap().is_dir() {
            append_files(root, &path, bytes);
        } else {
            bytes.extend_from_slice(&fs::read(&path).unwrap());
        }
    }
}

fn git_output(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .arg(format!("--git-dir={}", root.display()))
        .args(args)
        .output()
        .unwrap()
}
