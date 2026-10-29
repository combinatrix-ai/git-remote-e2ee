//! One test per binary: it measures this process's peak memory, which other
//! tests running concurrently would disturb.
#![cfg(unix)]

mod support;

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{CARRIER_CHUNK_BYTES, GitStorage, ObjectKind, Storage};

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn peak_resident_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0);
    let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        peak
    } else {
        peak * 1024
    }
}

#[test]
fn oversized_carrier_chunks_are_rejected_without_being_read() {
    let temporary = tempfile::tempdir().unwrap();
    // Only test in this binary, so the process-global override is stable.
    unsafe {
        std::env::set_var(
            "GIT_REMOTE_E2EE_CACHE_DIR",
            temporary.path().join("carrier-cache"),
        )
    };
    let carrier = temporary.path().join("carrier.git");
    git(
        temporary.path(),
        &["init", "--bare", "-q", carrier.to_str().unwrap()],
    );
    let repository = EncryptedRepository::new(
        GitStorage::open(carrier.to_str().unwrap()).unwrap(),
        KeyFile::generate(),
        support::state_dir(),
    );
    repository.initialize("owner").unwrap();
    let (head_id, _) = repository.current_manifest().unwrap();
    let manifest = GitStorage::open(carrier.to_str().unwrap())
        .unwrap()
        .get_object(ObjectKind::Manifest, &head_id)
        .unwrap();

    let workdir = temporary.path().join("edit");
    git(
        temporary.path(),
        &[
            "clone",
            "-q",
            "-b",
            "main",
            carrier.to_str().unwrap(),
            workdir.to_str().unwrap(),
        ],
    );
    let chunk = workdir
        .join("manifests")
        .join(&head_id[..2])
        .join(&head_id)
        .join("00000000");
    let mut file = File::create(&chunk).unwrap();
    let block = vec![b'x'; 1024 * 1024];
    for _ in 0..CARRIER_CHUNK_BYTES / block.len() as u64 {
        file.write_all(&block).unwrap();
    }
    file.write_all(b"!").unwrap();
    drop(file);
    git(
        &workdir,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qam",
            "oversize",
        ],
    );
    git(&workdir, &["push", "-q", "origin", "main"]);
    fs::remove_dir_all(&workdir).unwrap();

    let storage = GitStorage::open(carrier.to_str().unwrap()).unwrap();
    let before = peak_resident_bytes();
    let history = storage
        .recovery_history(2048, 64 * 1024 * 1024)
        .unwrap()
        .unwrap();
    let grown = peak_resident_bytes().saturating_sub(before);

    assert_eq!(history.manifests[&head_id], manifest);
    assert!(
        grown < CARRIER_CHUNK_BYTES / 2,
        "reading history grew peak memory by {grown} bytes"
    );
}
