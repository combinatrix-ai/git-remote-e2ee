//! `e2ee::` storage URLs. A URL names a Git carrier, written the way Git
//! itself would accept it and optionally followed by `#<branch>`, unless it
//! starts with `dir:`, which names a directory backend.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

#[derive(Clone, PartialEq, Eq)]
pub enum StorageUrl {
    Directory(PathBuf),
    Git(String),
    TrustedLocalGit(String),
}

impl StorageUrl {
    /// The exact URL stored in Git configuration and passed to Git.
    pub fn to_config_string(&self) -> String {
        match self {
            Self::Directory(path) => format!("e2ee::dir:{}", path.display()),
            Self::Git(remote) => format!("e2ee::{remote}"),
            Self::TrustedLocalGit(remote) => format!("e2ee::trusted-local:{remote}"),
        }
    }

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
        if is_git_helper_address(remote) {
            bail!("Git remote-helper syntax is not allowed for a carrier")
        }
        if is_local_git_carrier(remote) {
            bail!(
                "local Git carrier requires e2ee::trusted-local:/absolute/path; use e2ee::dir:/path for untrusted local storage"
            )
        }
        if !has_supported_git_scheme(remote) {
            bail!("unsupported Git carrier URL scheme")
        }
        Ok(Self::Git(address.to_owned()))
    }
}

/// An unknown `scheme://` invokes a user-installed Git remote helper.
pub(crate) fn has_supported_git_scheme(address: &str) -> bool {
    match address.split_once("://") {
        Some((scheme, _)) => matches!(scheme, "http" | "https" | "git" | "ssh"),
        None => true,
    }
}

/// Git's `name::address` form launches a `git-remote-name` executable.
pub(crate) fn is_git_helper_address(address: &str) -> bool {
    match address.find("::") {
        Some(helper) => address.find("://").is_none_or(|url| helper < url),
        None => false,
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
            Self::Directory(path) => write!(
                formatter,
                "e2ee::dir:{}",
                escape_terminal_controls(&path.display().to_string())
            ),
            Self::Git(remote) => write!(
                formatter,
                "e2ee::{}",
                escape_terminal_controls(&redact_carrier_address(remote))
            ),
            Self::TrustedLocalGit(remote) => write!(
                formatter,
                "e2ee::trusted-local:{}",
                escape_terminal_controls(remote)
            ),
        }
    }
}

impl fmt::Debug for StorageUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("StorageUrl")
            .field(&self.to_string())
            .finish()
    }
}

pub fn redact_carrier_address(address: &str) -> String {
    if let Some(scheme) = address.find("://") {
        let authority_start = scheme + 3;
        let authority_end = address[authority_start..]
            .find(['/', '?', '#'])
            .map_or(address.len(), |offset| authority_start + offset);
        let authority = &address[authority_start..authority_end];
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let suffix = if authority_end < address.len() {
            "/[redacted]"
        } else {
            ""
        };
        return format!("{}{host}{suffix}", &address[..authority_start]);
    }
    if let Some((host, _)) = address.split_once(':') {
        let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
        return format!("{host}:[redacted]");
    }
    address.to_owned()
}

/// Removes credential-bearing parts of scheme URLs from diagnostic text.
pub fn redact_diagnostic(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(offset) = input[search..].find("://") {
        let scheme_end = search + offset;
        let mut start = scheme_end;
        while start > search
            && matches!(input.as_bytes()[start - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'.')
        {
            start -= 1;
        }
        if start == scheme_end || !input.as_bytes()[start].is_ascii_alphabetic() {
            search = scheme_end + 3;
            continue;
        }
        let end = input[scheme_end + 3..]
            .char_indices()
            .find(|(_, character)| character.is_whitespace())
            .map_or(input.len(), |(offset, _)| scheme_end + 3 + offset);
        output.push_str(&input[copied..start]);
        output.push_str(&redact_carrier_address(&input[start..end]));
        copied = end;
        search = end;
    }
    output.push_str(&input[copied..]);
    output
}

pub fn safe_diagnostic(input: &str) -> String {
    escape_terminal_controls(&redact_diagnostic(input))
}

pub fn safe_diagnostic_with_args(input: &str, args: &[&str]) -> String {
    let mut safe = input.to_owned();
    for arg in args {
        let redacted = redact_carrier_address(arg);
        if !arg.is_empty() && redacted != *arg {
            safe = safe.replace(arg, &redacted);
        }
    }
    safe_diagnostic(&safe)
}

fn escape_terminal_controls(input: &str) -> String {
    let mut safe = String::with_capacity(input.len());
    for character in input.chars() {
        if is_control_or_invisible(character) {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

pub fn is_control_or_invisible(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
        )
}

#[cfg(test)]
mod tests {
    use super::{StorageUrl, redact_diagnostic, safe_diagnostic, safe_diagnostic_with_args};

    #[test]
    fn remote_git_urls_pass_through_and_dir_prefix_selects_a_directory() {
        for remote in [
            "https://github.com/you/notes.git",
            "ssh://git@host/you/notes.git",
            "git@github.com:you/notes.git",
        ] {
            let parsed = StorageUrl::parse(&format!("e2ee::{remote}")).unwrap();
            assert_eq!(parsed, StorageUrl::Git(remote.to_owned()));
            assert_eq!(parsed.to_config_string(), format!("e2ee::{remote}"));
            assert!(!parsed.to_string().contains('@'));
            assert!(!parsed.to_string().contains("notes.git"));
            assert_eq!(StorageUrl::parse(remote).unwrap(), parsed);
        }
        assert_eq!(
            StorageUrl::parse("e2ee::dir:/srv/encrypted").unwrap(),
            StorageUrl::Directory("/srv/encrypted".into())
        );
    }

    #[test]
    fn carrier_branch_fragments_remain_in_config() {
        for url in [
            "e2ee::https://host/x.git#vault",
            "e2ee::git@github.com:you/notes.git#team/vault",
        ] {
            let parsed = StorageUrl::parse(url).unwrap();
            assert_eq!(
                parsed,
                StorageUrl::Git(url.strip_prefix("e2ee::").unwrap().to_owned())
            );
            assert_eq!(parsed.to_config_string(), url);
            assert!(!parsed.to_string().contains("notes.git"));
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

    #[test]
    fn executable_remote_helper_forms_are_rejected() {
        for remote in [
            "ext::sh -c true",
            "ssh::host",
            "https::host",
            "foo://host/repo.git",
        ] {
            assert!(StorageUrl::parse(&format!("e2ee::{remote}")).is_err());
        }
        assert!(StorageUrl::parse("e2ee::ssh://[::1]/repo.git").is_ok());
    }

    #[test]
    fn carrier_url_diagnostics_hide_userinfo_and_query_but_keep_raw_config() {
        let raw = "e2ee::https://alice:secret@host/repo.git?access_token=token#vault";
        let parsed = StorageUrl::parse(raw).unwrap();
        assert_eq!(parsed.to_config_string(), raw);
        assert_eq!(parsed.to_string(), "e2ee::https://host/[redacted]");
        assert!(!format!("{parsed:?}").contains("secret"));
        assert!(!format!("{parsed:?}").contains("token"));
        assert_eq!(
            redact_diagnostic(
                "git failed for 'https://alice:secret@host/repo.git?access_token=token'"
            ),
            "git failed for 'https://host/[redacted]"
        );
        assert_eq!(
            redact_diagnostic("https://alice:secret@host/repo.git?token='hidden'"),
            "https://host/[redacted]"
        );
        let scp = StorageUrl::parse("e2ee::alice@host:private-token/repo.git").unwrap();
        assert_eq!(scp.to_string(), "e2ee::host:[redacted]");
        assert_eq!(
            safe_diagnostic_with_args(
                "fatal: unable to access 'host:private-token'",
                &["host:private-token"]
            ),
            "fatal: unable to access 'host:[redacted]'"
        );
        assert_eq!(
            safe_diagnostic("invalid field\n\r\u{1b}]52;c;clipboard\u{7}"),
            "invalid field\\n\\r\\u{1b}]52;c;clipboard\\u{7}"
        );
        assert_eq!(safe_diagnostic("a\u{200b}b"), "a\\u{200b}b");
        let local = StorageUrl::Directory("/tmp/unsafe\u{1b}[31m".into());
        assert_eq!(local.to_string(), "e2ee::dir:/tmp/unsafe\\u{1b}[31m");
        assert_eq!(local.to_config_string(), "e2ee::dir:/tmp/unsafe\u{1b}[31m");
    }
}
