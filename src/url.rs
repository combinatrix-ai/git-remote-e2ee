//! `e2ee::` storage URLs. A URL names a Git carrier, written the way Git
//! itself would accept it and optionally followed by `#<branch>`, unless it
//! starts with `dir:`, which names a directory backend.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageUrl {
    Directory(PathBuf),
    Git(String),
    TrustedLocalGit(String),
}

impl StorageUrl {
    /// Relative local paths are resolved against the current directory, so
    /// the result can be stored in Git config and used from anywhere.
    pub fn parse(url: &str) -> Result<Self> {
        let address = url.strip_prefix("e2ee::").unwrap_or(url);
        if let Some(path) = address.strip_prefix("dir:") {
            if path.is_empty() {
                bail!("empty directory path in storage URL {url:?}")
            }
            return Ok(Self::Directory(std::path::absolute(path)?));
        }
        if address.is_empty() {
            bail!("empty storage URL")
        }
        if let Some(location) = address.strip_prefix("trusted-local:") {
            let remote = location.split('#').next().unwrap_or_default();
            if !Path::new(remote).is_absolute() {
                bail!("trusted-local Git carrier requires an absolute path")
            }
            return Ok(Self::TrustedLocalGit(location.to_owned()));
        }
        let remote = address.split('#').next().unwrap_or_default();
        if is_local_git_carrier(remote) {
            bail!(
                "local Git carrier requires e2ee::trusted-local:/absolute/path; use e2ee::dir:/path for untrusted local storage"
            )
        }
        Ok(Self::Git(address.to_owned()))
    }
}

/// Whether Git treats the address as a local path or file transport rather
/// than a network URL or scp-style address. Transport policy also forbids
/// rewrites to local paths after parsing.
pub(crate) fn is_local_git_carrier(address: &str) -> bool {
    if address.starts_with("file://") {
        return true;
    }
    if address.contains("://") || address.contains("::") {
        return false;
    }
    if Path::new(address).is_absolute() {
        return true;
    }
    #[cfg(windows)]
    if matches!(
        Path::new(address).components().next(),
        Some(std::path::Component::Prefix(_))
    ) {
        return true;
    }
    match address.find(':') {
        Some(colon) if colon > 0 => {
            let slash = address.find(['/', '\\']);
            slash.is_some_and(|slash| slash < colon)
        }
        _ => true,
    }
}

impl fmt::Display for StorageUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) => write!(formatter, "e2ee::dir:{}", path.display()),
            Self::Git(remote) => write!(formatter, "e2ee::{remote}"),
            Self::TrustedLocalGit(remote) => write!(formatter, "e2ee::trusted-local:{remote}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StorageUrl;

    #[test]
    fn remote_git_urls_pass_through_and_dir_prefix_selects_a_directory() {
        for remote in [
            "https://github.com/you/notes.git",
            "ssh://git@host/you/notes.git",
            "git@github.com:you/notes.git",
        ] {
            let parsed = StorageUrl::parse(&format!("e2ee::{remote}")).unwrap();
            assert_eq!(parsed, StorageUrl::Git(remote.to_owned()));
            assert_eq!(parsed.to_string(), format!("e2ee::{remote}"));
            assert_eq!(StorageUrl::parse(remote).unwrap(), parsed);
        }
        assert_eq!(
            StorageUrl::parse("e2ee::dir:/srv/encrypted").unwrap(),
            StorageUrl::Directory("/srv/encrypted".into())
        );
    }

    #[test]
    fn carrier_branch_fragments_round_trip_unchanged() {
        for url in [
            "e2ee::https://host/x.git#vault",
            "e2ee::git@github.com:you/notes.git#team/vault",
        ] {
            let parsed = StorageUrl::parse(url).unwrap();
            assert_eq!(
                parsed,
                StorageUrl::Git(url.strip_prefix("e2ee::").unwrap().to_owned())
            );
            assert_eq!(parsed.to_string(), url);
        }
    }

    #[test]
    fn directory_paths_become_absolute_and_local_git_requires_opt_in() {
        let current = std::env::current_dir().unwrap();
        assert_eq!(
            StorageUrl::parse("e2ee::dir:store").unwrap(),
            StorageUrl::Directory(current.join("store"))
        );
        for local in [
            "src",
            "./src",
            "../src",
            "/srv/carrier.git",
            "file:///srv/carrier.git",
            "./host:path",
            "foo/bar:baz",
        ] {
            assert!(StorageUrl::parse(&format!("e2ee::{local}")).is_err());
        }
        assert!(StorageUrl::parse("e2ee::trusted-local:src").is_err());
        let trusted = format!(
            "e2ee::trusted-local:{}#vault",
            current.join("src").display()
        );
        assert_eq!(
            StorageUrl::parse(&trusted).unwrap(),
            StorageUrl::TrustedLocalGit(format!("{}#vault", current.join("src").display()))
        );
        assert_eq!(StorageUrl::parse(&trusted).unwrap().to_string(), trusted);
    }

    #[test]
    fn empty_addresses_are_rejected() {
        assert!(StorageUrl::parse("e2ee::").is_err());
        assert!(StorageUrl::parse("e2ee::dir:").is_err());
    }
}
