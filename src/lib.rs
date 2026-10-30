/// The one format number. Storage layout, manifests, policies, ciphertext
/// magics, and every domain-separation string carry it.
macro_rules! format_version {
    () => {
        "6"
    };
}

/// Domain-separation tag `git-remote-e2ee <purpose> v<format>\0`.
macro_rules! domain {
    ($purpose:literal) => {
        concat!("git-remote-e2ee ", $purpose, " v", format_version!(), "\0").as_bytes()
    };
}

mod bounded;
mod catfile;
pub mod continuity;
pub mod crypto;
pub mod error;
pub mod git;
pub mod gitcmd;
pub mod manifest;
mod persist;
pub mod policy;
mod refname;
pub mod repository;
pub mod storage;
mod trace;
pub mod url;

pub const FORMAT_VERSION: u32 = {
    let digits = format_version!().as_bytes();
    assert!(digits.len() == 1);
    (digits[0] - b'0') as u32
};
