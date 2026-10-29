//! The single place that spawns `git`. Every command names its repository
//! explicitly and runs under one of two environment policies:
//!
//! - The user's repository: addressed by its absolute Git directory, with the
//!   inherited repository-selecting variables removed so they cannot redirect
//!   the command elsewhere. The user's configuration applies.
//! - A repository this program owns (carrier cache, carrier checkout,
//!   recovery's scratch repository): repository selection and injected
//!   command-line configuration are removed, and incidental behaviour such as
//!   hooks and signing is disabled. Global and system configuration still
//!   apply, because carrier transport needs credentials, ssh, proxies, and
//!   `url.*.insteadOf`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};

/// Variables through which an environment selects a repository, its object
/// store, its history, or extra configuration.
const REPOSITORY_SELECTION: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_GRAFT_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
];

/// Configuration injected by `git -c` or `GIT_CONFIG_COUNT` in the caller.
/// It targets the user's repository, never one this program owns.
const INJECTED_CONFIG: &[&str] = &["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG"];

/// Identity and dates a caller may export for its own commits.
const COMMIT_IDENTITY: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
];

/// Settings that keep commands on owned repositories free of user hooks,
/// signing, and prompts. `/dev/null` is not a directory, so no hook exists.
const OWNED_REPOSITORY_CONFIG: &[&str] = &[
    "core.hooksPath=/dev/null",
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "push.gpgSign=false",
    "core.fsmonitor=false",
];

/// A Git repository every command names explicitly, with the environment
/// policy of whoever owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRepository {
    location: Location,
    owner: Owner,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Location {
    /// An absolute Git directory, used without a work tree.
    GitDir(PathBuf),
    /// A non-bare repository's work tree; commands run inside it.
    WorkTree(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    User,
    Program,
}

impl GitRepository {
    /// The user's repository that Git selected for this process: `GIT_DIR`
    /// when Git exported it (as it does for remote helpers and
    /// `git <command>`), otherwise discovery from the working directory.
    /// `None` outside any repository.
    pub fn from_environment() -> Result<Option<Self>> {
        let output = Command::new("git")
            .args(["rev-parse", "--absolute-git-dir"])
            .output()?;
        Self::parse_discovery(output)
    }

    /// The user's repository at `path`, ignoring any repository the
    /// environment selects.
    pub fn open(path: &Path) -> Result<Self> {
        let mut command = Command::new("git");
        remove_all(&mut command, REPOSITORY_SELECTION);
        let output = command
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "--absolute-git-dir"])
            .output()?;
        match Self::parse_discovery(output)? {
            Some(repository) => Ok(repository),
            None => bail!("{} is not a Git repository", path.display()),
        }
    }

    /// What `--repo` means for every command: the named repository, or the
    /// one the environment selects.
    pub fn resolve(path: Option<&Path>) -> Result<Option<Self>> {
        match path {
            Some(path) => Self::open(path).map(Some),
            None => Self::from_environment(),
        }
    }

    fn parse_discovery(output: std::process::Output) -> Result<Option<Self>> {
        if !output.status.success() {
            return Ok(None);
        }
        let git_dir = PathBuf::from(String::from_utf8(output.stdout)?.trim_end_matches('\n'));
        if !git_dir.is_absolute() {
            bail!("git rev-parse returned a relative Git directory")
        }
        Ok(Some(Self {
            location: Location::GitDir(git_dir),
            owner: Owner::User,
        }))
    }

    /// A bare repository or Git directory this program created.
    pub(crate) fn owned_git_dir(path: &Path) -> Self {
        Self {
            location: Location::GitDir(path.to_path_buf()),
            owner: Owner::Program,
        }
    }

    /// A non-bare repository this program created, addressed by its work tree.
    pub(crate) fn owned_work_tree(path: &Path) -> Self {
        Self {
            location: Location::WorkTree(path.to_path_buf()),
            owner: Owner::Program,
        }
    }

    /// A command on this owned repository that talks to the carrier remote.
    /// Unlike `git()`, it keeps configuration the caller injected with
    /// `git -c` (proxies, credential helpers, `insteadOf` rewrites), which
    /// transport needs; the owned-repository overrides are appended after it,
    /// so they still win for hooks and signing.
    pub(crate) fn transport(&self) -> Command {
        debug_assert_eq!(self.owner, Owner::Program);
        let mut command = Command::new("git");
        remove_all(&mut command, REPOSITORY_SELECTION);
        remove_all(&mut command, COMMIT_IDENTITY);
        for setting in OWNED_REPOSITORY_CONFIG {
            command.arg("-c").arg(setting);
        }
        match &self.location {
            Location::GitDir(path) => command.arg("--git-dir").arg(path),
            Location::WorkTree(path) => command.arg("-C").arg(path),
        };
        command
    }

    /// The user's Git directory, where per-repository state lives.
    pub fn git_dir(&self) -> PathBuf {
        match &self.location {
            Location::GitDir(path) => path.clone(),
            Location::WorkTree(path) => path.join(".git"),
        }
    }

    /// A `git` command bound to this repository.
    pub fn git(&self) -> Command {
        let mut command = match self.owner {
            Owner::User => {
                let mut command = Command::new("git");
                remove_all(&mut command, REPOSITORY_SELECTION);
                command
            }
            Owner::Program => without_repository(),
        };
        match &self.location {
            Location::GitDir(path) => command.arg("--git-dir").arg(path),
            Location::WorkTree(path) => command.arg("-C").arg(path),
        };
        command
    }
}

/// A `git` command that touches no repository (`init`, `check-ref-format`),
/// under the policy for repositories this program owns.
pub(crate) fn without_repository() -> Command {
    let mut command = Command::new("git");
    remove_all(&mut command, REPOSITORY_SELECTION);
    remove_all(&mut command, INJECTED_CONFIG);
    remove_all(&mut command, COMMIT_IDENTITY);
    for setting in OWNED_REPOSITORY_CONFIG {
        command.arg("-c").arg(setting);
    }
    command
}

fn remove_all(command: &mut Command, variables: &[&str]) {
    for variable in variables {
        command.env_remove(variable);
    }
}
