//! Local state shared by one test binary. Continuity floors are keyed by
//! repository root and every test generates its own root, so tests in one
//! binary act like one machine without sharing floors.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The `XDG_STATE_HOME` that Git commands running the helper must see.
pub fn state_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("state-home")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap()
            .keep()
    })
}

/// The state directory the library takes: `$XDG_STATE_HOME/git-e2ee`.
pub fn state_dir() -> PathBuf {
    state_home().join("git-e2ee")
}

/// This machine's continuity floor file for `repository_root`.
pub fn floor_path(repository_root: &str) -> PathBuf {
    state_dir().join(repository_root).join("continuity.json")
}

pub fn read_floor(repository_root: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(floor_path(repository_root)).unwrap()).unwrap()
}
