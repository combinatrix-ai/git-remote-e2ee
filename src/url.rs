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
        let (path, fragment) = match address.rsplit_once('#') {
            Some((path, branch)) => (path, Some(branch)),
            None => (address, None),
        };
        let local = Path::new(path);
        if local.is_relative() && local.exists() {
            let mut absolute = std::path::absolute(local)?.to_string_lossy().into_owned();
            if let Some(branch) = fragment {
                absolute.push('#');
                absolute.push_str(branch);
            }
            return Ok(Self::Git(absolute));
        }
        Ok(Self::Git(address.to_owned()))
    }
}

impl fmt::Display for StorageUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) => write!(formatter, "e2ee::dir:{}", path.display()),
            Self::Git(remote) => write!(formatter, "e2ee::{remote}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StorageUrl;

    #[test]
    fn git_urls_pass_through_and_dir_prefix_selects_a_directory() {
        for remote in [
            "https://github.com/you/notes.git",
            "ssh://git@host/you/notes.git",
            "git@github.com:you/notes.git",
            "file:///srv/carrier.git",
            "/srv/carrier.git",
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
            "e2ee::/srv/carrier.git#vault",
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
    fn relative_paths_become_absolute() {
        let current = std::env::current_dir().unwrap();
        assert_eq!(
            StorageUrl::parse("e2ee::dir:store").unwrap(),
            StorageUrl::Directory(current.join("store"))
        );
        assert_eq!(
            StorageUrl::parse("e2ee::src").unwrap(),
            StorageUrl::Git(current.join("src").to_string_lossy().into_owned())
        );
        assert_eq!(
            StorageUrl::parse("e2ee::src#vault").unwrap(),
            StorageUrl::Git(format!("{}#vault", current.join("src").display()))
        );
    }

    #[test]
    fn empty_addresses_are_rejected() {
        assert!(StorageUrl::parse("e2ee::").is_err());
        assert!(StorageUrl::parse("e2ee::dir:").is_err());
    }
}
