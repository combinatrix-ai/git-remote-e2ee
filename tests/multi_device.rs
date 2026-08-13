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
fn revocation_rotates_epoch_rewraps_history_and_blocks_future_access() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote");
    let source = temp.path().join("source");
    let admin_pin = temp.path().join("a-admin-state.json");
    initialize_git(&source);

    let key_a = KeyFile::generate();
    let key_b = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let key_c = KeyFile::generate_for_repository(key_a.repository_root.clone()).unwrap();
    let repo_a = EncryptedRepository::new(FilesystemStorage::new(&remote), key_a.clone());
    repo_a.initialize().unwrap();
    repo_a.pin_admin_state(&admin_pin).unwrap();
    commit(&source, "before revoke\n", "before revoke");
    repo_a.push_ref(&source, "refs/heads/main", false).unwrap();
    commit(&source, "second pack\n", "second pack");
    repo_a.push_ref(&source, "refs/heads/main", false).unwrap();
    repo_a
        .add_device(
            key_b.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    let before_revoke = temp.path().join("before-revoke");
    copy_directory(&remote, &before_revoke);

    repo_a
        .revoke_device(&key_b.device_id().unwrap(), &admin_pin)
        .unwrap();
    let repo_b = EncryptedRepository::new(FilesystemStorage::new(&remote), key_b.clone());
    assert!(repo_b.current_manifest().is_err());
    let old_repo_b = EncryptedRepository::new(FilesystemStorage::new(&before_revoke), key_b);
    assert_eq!(old_repo_b.current_manifest().unwrap().1.packs.len(), 2);

    repo_a
        .add_device(
            key_c.public_device().unwrap(),
            DeviceRoles::collaborator(),
            &admin_pin,
        )
        .unwrap();
    let destination = temp.path().join("destination");
    initialize_git(&destination);
    let repo_c = EncryptedRepository::new(FilesystemStorage::new(&remote), key_c);
    let manifest = repo_c.fetch_into(&destination, "e2ee").unwrap();
    repo_c.verify().unwrap();
    assert_eq!(manifest.packs.len(), 2);
    assert_eq!(
        git(&destination, &["show", "refs/remotes/e2ee/main:note.md"]),
        "second pack"
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
