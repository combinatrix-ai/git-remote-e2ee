use std::fs;
use std::path::Path;
use std::process::Command;

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::FilesystemStorage;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn initialize_git(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["config", "user.name", "Multi Device Test"]);
    git(
        repo,
        &["config", "user.email", "multi-device@example.invalid"],
    );
}

fn commit(repo: &Path, contents: &str, message: &str) -> String {
    fs::write(repo.join("note.md"), contents).unwrap();
    git(repo, &["add", "note.md"]);
    git(repo, &["commit", "-q", "-m", message]);
    git(repo, &["rev-parse", "HEAD"])
}

#[test]
fn two_devices_can_decrypt_and_push_independently() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let source_a = temp.path().join("a");
    let source_b = temp.path().join("b");
    let admin_pin = temp.path().join("a-admin-state.json");
    initialize_git(&source_a);
    initialize_git(&source_b);

    let key_a = KeyFile::generate();
    let key_b = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let repo_a = EncryptedRepository::new(FilesystemStorage::new(&remote), key_a.clone());
    repo_a.initialize().unwrap();
    repo_a.pin_admin_state(&admin_pin).unwrap();
    let first = commit(&source_a, "from a\n", "from a");
    repo_a
        .push_ref(&source_a, "refs/heads/main", false)
        .unwrap();
    repo_a
        .add_device(
            key_b.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();

    let repo_b = EncryptedRepository::new(FilesystemStorage::new(&remote), key_b.clone());
    repo_b.fetch_into(&source_b, "e2ee").unwrap();
    assert_eq!(
        git(&source_b, &["rev-parse", "refs/remotes/e2ee/main"]),
        first
    );
    git(
        &source_b,
        &["switch", "-q", "-c", "main", "refs/remotes/e2ee/main"],
    );
    let second = commit(&source_b, "from b\n", "from b");
    repo_b
        .push_ref(&source_b, "refs/heads/main", false)
        .unwrap();

    let destination = temp.path().join("destination");
    initialize_git(&destination);
    repo_a.fetch_into(&destination, "e2ee").unwrap();
    assert_eq!(
        git(&destination, &["rev-parse", "refs/remotes/e2ee/main"]),
        second
    );
}

#[test]
fn revoked_reader_cannot_reach_later_history_but_keeps_prior_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let source = temp.path().join("source");
    let client_b = temp.path().join("client-b");
    let admin_pin = temp.path().join("a-admin-state.json");
    initialize_git(&source);
    initialize_git(&client_b);

    let key_a = KeyFile::generate();
    let key_b = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let key_c = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let repo_a = EncryptedRepository::new(FilesystemStorage::new(&remote), key_a.clone());
    repo_a.initialize().unwrap();
    repo_a.pin_admin_state(&admin_pin).unwrap();
    let before = commit(&source, "before revoke\n", "before revoke");
    repo_a.push_ref(&source, "refs/heads/main", false).unwrap();
    let before_tip = commit(&source, "second pack\n", "second pack");
    repo_a.push_ref(&source, "refs/heads/main", false).unwrap();
    assert_eq!(count_files(&remote.join("objects")), 2);
    repo_a
        .add_device(
            key_b.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    assert_eq!(count_files(&remote.join("objects")), 2);
    let repo_b = EncryptedRepository::new(FilesystemStorage::new(&remote), key_b.clone());
    repo_b.fetch_into(&client_b, "e2ee").unwrap();
    assert_eq!(
        git(&client_b, &["show", "refs/remotes/e2ee/main:note.md"]),
        "second pack"
    );
    git(
        &client_b,
        &["switch", "-q", "-c", "main", "refs/remotes/e2ee/main"],
    );
    let before_revoke = temp.path().join("before-revoke");
    copy_directory(&remote, &before_revoke);
    let old_objects = snapshot_files(&remote.join("objects"));

    repo_a
        .revoke_device(&key_b.device_id().unwrap(), &admin_pin)
        .unwrap();
    assert_eq!(count_files(&remote.join("objects")), 2);
    assert!(repo_b.current_manifest().is_err());

    let after = commit(&source, "after revoke secret\n", "after revoke");
    repo_a.push_ref(&source, "refs/heads/main", false).unwrap();
    assert_eq!(count_files(&remote.join("objects")), 3);
    for (path, contents) in old_objects {
        assert_eq!(fs::read(path).unwrap(), contents);
    }

    let fetch_error = repo_b
        .fetch_into(&client_b, "e2ee")
        .unwrap_err()
        .to_string();
    assert!(
        fetch_error.contains("not an active reader"),
        "unexpected fetch error: {fetch_error}"
    );
    assert_eq!(
        git(&client_b, &["rev-parse", "refs/remotes/e2ee/main"]),
        before_tip
    );
    assert!(!git_status(&client_b, &["cat-file", "-e", &after]));

    commit(&client_b, "revoked writer\n", "revoked writer");
    let push_error = repo_b
        .push_update_for_remote(
            &client_b,
            "e2ee",
            "refs/heads/main",
            "refs/heads/main",
            false,
        )
        .unwrap_err()
        .to_string();
    assert!(
        push_error.contains("not an active reader"),
        "unexpected push error: {push_error}"
    );
    assert!(repo_b.verify().is_err());

    let snapshot_destination = temp.path().join("snapshot-destination");
    initialize_git(&snapshot_destination);
    let old_repo_b =
        EncryptedRepository::new(FilesystemStorage::new(&before_revoke), key_b.clone());
    old_repo_b
        .fetch_into(&snapshot_destination, "snapshot")
        .unwrap();
    assert_eq!(
        git(
            &snapshot_destination,
            &["show", "refs/remotes/snapshot/main:note.md"]
        ),
        "second pack"
    );
    assert_eq!(
        git(
            &snapshot_destination,
            &["show", &format!("{before}:note.md")]
        ),
        "before revoke"
    );

    repo_a
        .add_device(
            key_c.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    assert_eq!(count_files(&remote.join("objects")), 3);
    let destination = temp.path().join("destination");
    initialize_git(&destination);
    let repo_c = EncryptedRepository::new(FilesystemStorage::new(&remote), key_c);
    let manifest = repo_c.fetch_into(&destination, "e2ee").unwrap();
    repo_c.verify().unwrap();
    assert_eq!(manifest.total_pack_count, 3);
    assert_eq!(
        git(&destination, &["show", "refs/remotes/e2ee/main:note.md"]),
        "after revoke secret"
    );
    assert_eq!(
        git(&destination, &["show", &format!("{before}:note.md")]),
        "before revoke"
    );
}

#[test]
fn membership_observation_pins_head_without_skipping_later_pack_import() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let source = temp.path().join("source");
    let client = temp.path().join("client");
    let admin_pin = temp.path().join("admin-state.json");
    initialize_git(&source);
    initialize_git(&client);

    let key_a = KeyFile::generate();
    let key_b = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), key_a);
    repository.initialize().unwrap();
    repository.pin_admin_state(&admin_pin).unwrap();
    commit(&source, "one\n", "one");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&client, "e2ee").unwrap();
    let before_membership = fs::read_to_string(remote.join("HEAD")).unwrap();

    repository
        .add_device(
            key_b.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    repository.observe_manifest(&client, "e2ee").unwrap();
    let after_membership = fs::read_to_string(remote.join("HEAD")).unwrap();

    fs::write(remote.join("HEAD"), &before_membership).unwrap();
    let error = repository
        .observe_manifest(&client, "e2ee")
        .unwrap_err()
        .to_string();
    assert!(error.contains("rolled back"), "unexpected error: {error}");

    fs::write(remote.join("HEAD"), after_membership).unwrap();
    commit(&source, "two\n", "two");
    repository
        .push_ref(&source, "refs/heads/main", false)
        .unwrap();
    repository.fetch_into(&client, "e2ee").unwrap();
    assert_eq!(
        git(&client, &["show", "refs/remotes/e2ee/main:note.md"]),
        "two"
    );
}

#[test]
fn administrative_pin_rejects_policy_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let pin = temp.path().join("admin-state.json");
    let owner = KeyFile::generate();
    let first = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let second = KeyFile::generate_for_repository(owner.repository_root.clone()).unwrap();
    let repository = EncryptedRepository::new(FilesystemStorage::new(&remote), owner);
    let genesis = repository.initialize().unwrap();
    repository.pin_admin_state(&pin).unwrap();
    repository
        .add_device(
            first.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &pin,
        )
        .unwrap();

    fs::write(remote.join("HEAD"), format!("{genesis}\n")).unwrap();
    assert!(
        repository
            .add_device(
                second.public_device().unwrap(),
                DeviceRoles::collaborator(),
                &pin,
            )
            .unwrap_err()
            .to_string()
            .contains("rolled back")
    );
}

#[test]
fn non_admin_device_cannot_change_policy() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let key_a = KeyFile::generate();
    let key_b = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let key_c = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let admin_pin = temp.path().join("a-admin-state.json");
    let non_admin_pin = temp.path().join("b-admin-state.json");
    let repo_a = EncryptedRepository::new(FilesystemStorage::new(&remote), key_a);
    repo_a.initialize().unwrap();
    repo_a.pin_admin_state(&admin_pin).unwrap();
    repo_a
        .add_device(
            key_b.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    let repo_b = EncryptedRepository::new(FilesystemStorage::new(&remote), key_b);
    assert!(
        repo_b
            .add_device(
                key_c.public_device().unwrap(),
                DeviceRoles::collaborator(),
                &non_admin_pin,
            )
            .unwrap_err()
            .to_string()
            .contains("not an active administrator")
    );
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn count_files(path: &Path) -> usize {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                count_files(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

fn snapshot_files(path: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    if !path.exists() {
        return files;
    }
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            files.extend(snapshot_files(&entry.path()));
        } else {
            files.push((entry.path(), fs::read(entry.path()).unwrap()));
        }
    }
    files
}

fn git_status(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap()
        .status
        .success()
}
