use std::path::PathBuf;
use std::process::Command as Process;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use git_remote_e2ee::continuity::default_state_dir;
use git_remote_e2ee::crypto::{KeyFile, PublicDevice};
use git_remote_e2ee::gitcmd::GitRepository;
use git_remote_e2ee::policy::{DeviceRoles, validate_device_label};
use git_remote_e2ee::repository::{
    EncryptedRepository, InitializeError, RecoveryOptions, RecoveryReport,
};
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage};
use git_remote_e2ee::url::StorageUrl;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DeviceRole {
    Read,
    Write,
    Admin,
}

impl From<DeviceRole> for DeviceRoles {
    fn from(role: DeviceRole) -> Self {
        match role {
            DeviceRole::Read => Self::reader(),
            DeviceRole::Write => Self::collaborator(),
            DeviceRole::Admin => Self::owner(),
        }
    }
}

/// Commands that act on existing storage take a TARGET: a Git remote name such
/// as `origin`, whose URL and key come from Git config, or a storage URL such
/// as `e2ee::https://host/you/repo.git` or `e2ee::dir:/srv/repo`.
#[derive(Subcommand)]
enum Command {
    /// Create a private device key
    Keygen {
        /// Defaults to $XDG_CONFIG_HOME/git-e2ee/keys/<repository-root>.json
        #[arg(long)]
        output: Option<PathBuf>,
        /// Create a key for another device of an existing repository
        #[arg(long)]
        repository_root: Option<String>,
    },
    /// Write the public half of a device key, to send to an administrator
    DeviceExport {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Initialize encrypted storage; inside a Git repository, also add it as a remote
    Init {
        /// Storage URL, for example https://host/you/repo.git or e2ee::dir:/srv/repo
        url: String,
        /// Key to use; created there if missing. Defaults to a new key under
        /// $XDG_CONFIG_HOME/git-e2ee/keys/
        #[arg(long)]
        key: Option<PathBuf>,
        /// Name of the Git remote to add
        #[arg(long, default_value = "origin")]
        name: String,
        /// Label shown for this device in `device-list`. Defaults to the hostname
        #[arg(long)]
        label: Option<String>,
    },
    /// Check the whole manifest chain and every pack
    Verify {
        target: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    DeviceAdd {
        target: String,
        /// Public device file from `git-e2ee device-export`
        device: PathBuf,
        /// Label shown in `device-list`; unique among active devices
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "write")]
        role: DeviceRole,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    DeviceRevoke {
        target: String,
        device_id: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    DeviceList {
        target: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    Recover {
        target: String,
        #[arg(long)]
        key: Option<PathBuf>,
        /// Repository whose remotes, key, and recovery state apply. Defaults
        /// to the repository Git selects for the current directory
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        publish: bool,
        #[arg(long, requires = "publish")]
        base: Option<String>,
        #[arg(long, requires = "publish")]
        discard_newer: bool,
        #[arg(long, requires = "publish")]
        accept_stale_floor: bool,
    },
}

struct Target {
    storage: StorageUrl,
    key: PathBuf,
}

impl Target {
    /// Resolves a remote name through `repository`'s configuration, or takes
    /// `target` as a storage URL.
    fn resolve(
        target: &str,
        key: Option<PathBuf>,
        repository: Option<&GitRepository>,
    ) -> Result<Self> {
        let configured = match repository {
            Some(repository) if !target.starts_with("e2ee::") => {
                git_config(repository, &format!("remote.{target}.url"), false)?
            }
            _ => None,
        };
        let (url, configured_key) = match (configured, repository) {
            (Some(url), Some(repository)) if url.starts_with("e2ee::") => {
                let key = git_config(repository, &format!("remote.{target}.e2ee-key"), true)?;
                (url, key.map(PathBuf::from))
            }
            (Some(url), _) => bail!("Git remote {target} is not an e2ee:: remote ({url})"),
            (None, _) if target.starts_with("e2ee::") || target.contains(['/', ':']) => {
                (target.to_owned(), None)
            }
            (None, _) => bail!(
                "no Git remote named {target}; give a storage URL such as e2ee::https://host/you/repo.git"
            ),
        };
        let key = key
            .or(configured_key)
            .with_context(|| format!("no key configured for {target}; pass --key <path>"))?;
        Ok(Self {
            storage: StorageUrl::parse(&url)?,
            key,
        })
    }
}

/// Opens the target's storage with its key and evaluates `$body` with the
/// repository bound to `$repository`, whichever backend the URL names.
macro_rules! with_repository {
    ($target:expr, |$repository:ident| $body:expr) => {{
        let target: &Target = $target;
        let key = KeyFile::read(&target.key)?;
        let state_dir = default_state_dir()?;
        match &target.storage {
            StorageUrl::Directory(path) => {
                let $repository =
                    EncryptedRepository::new(FilesystemStorage::new(path), key, state_dir);
                $body
            }
            StorageUrl::Git(remote) => {
                let $repository =
                    EncryptedRepository::new(GitStorage::open(remote)?, key, state_dir);
                $body
            }
        }
    }};
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen {
            output,
            repository_root,
        } => {
            let key = match repository_root {
                Some(root) => KeyFile::generate_for_repository(root)?,
                None => KeyFile::generate(),
            };
            let output = match output {
                Some(path) => path,
                None => default_key_path(&key.repository_root)?,
            };
            key.write_new(&output)?;
            println!(
                "created {} for repository root {}",
                output.display(),
                key.repository_root
            );
        }
        Command::DeviceExport { key, output } => {
            let public = KeyFile::read(&key)?.public_device()?;
            public.write_new(&output)?;
            println!(
                "exported device {} to {}",
                public.device_id,
                output.display()
            );
        }
        Command::Init {
            url,
            key,
            name,
            label,
        } => {
            let storage = StorageUrl::parse(&url)?;
            let label = match label {
                Some(label) => label,
                None => default_owner_label(),
            };
            validate_device_label(&label)?;
            let local = GitRepository::from_environment()?;
            if let Some(local) = &local
                && git_config(local, &format!("remote.{name}.url"), false)?.is_some()
            {
                bail!("Git remote {name} already exists; choose another name with --name")
            }
            let mut created_key = None;
            let key = match key {
                Some(path) if path.exists() => path,
                requested => {
                    let generated = KeyFile::generate();
                    let path = match requested {
                        Some(path) => path,
                        None => default_key_path(&generated.repository_root)?,
                    };
                    generated.write_new(&path)?;
                    println!("created key {} (administrator)", path.display());
                    created_key = Some(path.clone());
                    path
                }
            };
            let attempt = (|| -> Result<(Target, Result<String, InitializeError>)> {
                let target = Target {
                    storage,
                    key: std::path::absolute(key)?,
                };
                let outcome = with_repository!(&target, |repository| repository.initialize(&label));
                Ok((target, outcome))
            })();
            let target = match attempt {
                Ok((target, Ok(_))) => target,
                Ok((_, Err(InitializeError::BeforePublication(error)))) | Err(error) => {
                    if let Some(path) = created_key {
                        let _ = std::fs::remove_file(path);
                    }
                    return Err(error);
                }
                Ok((target, Err(error))) => {
                    return Err(anyhow::Error::new(error).context(format!(
                        "kept key {}; it may be the only owner key for {}",
                        target.key.display(),
                        target.storage
                    )));
                }
            };
            println!("initialized {}", target.storage);
            if let Some(local) = &local {
                run_git(
                    local,
                    &["remote", "add", &name, &target.storage.to_string()],
                )?;
                run_git(
                    local,
                    &[
                        "config",
                        &format!("remote.{name}.e2ee-key"),
                        &target.key.to_string_lossy(),
                    ],
                )?;
                println!("added remote {name}");
            }
        }
        Command::Verify { target, key } => {
            let target =
                Target::resolve(&target, key, GitRepository::from_environment()?.as_ref())?;
            let manifest = with_repository!(&target, |repository| repository.verify()?);
            println!(
                "verified generation {} ({} refs, {} packs)",
                manifest.generation,
                manifest.refs.len(),
                manifest.total_pack_count
            );
        }
        Command::DeviceAdd {
            target,
            device,
            label,
            role,
            key,
        } => {
            let target =
                Target::resolve(&target, key, GitRepository::from_environment()?.as_ref())?;
            let public = PublicDevice::read(&device)?;
            let device_id = public.device_id.clone();
            let roles = DeviceRoles::from(role);
            let (manifest, policy) = with_repository!(&target, |repository| {
                repository.add_device(public, &label, roles)?
            });
            println!("added {device_id} ({label}); manifest {manifest}; policy {policy}");
        }
        Command::DeviceRevoke {
            target,
            device_id,
            key,
        } => {
            let target =
                Target::resolve(&target, key, GitRepository::from_environment()?.as_ref())?;
            let (manifest, policy) = with_repository!(&target, |repository| repository
                .revoke_device(&device_id)?);
            println!("revoked {device_id}; manifest {manifest}; policy {policy}");
        }
        Command::DeviceList { target, key } => {
            let target =
                Target::resolve(&target, key, GitRepository::from_environment()?.as_ref())?;
            let own_id = KeyFile::read(&target.key)?.device_id()?;
            let devices = with_repository!(&target, |repository| repository.list_devices()?);
            for device in devices {
                println!(
                    "{}{}  {}  role={}  status={}",
                    if device.public.device_id == own_id {
                        "* "
                    } else {
                        "  "
                    },
                    device.public.device_id,
                    device.label,
                    role_name(&device.roles),
                    if device.active() { "active" } else { "revoked" }
                );
            }
        }
        Command::Recover {
            target,
            key,
            repo,
            publish,
            base,
            discard_newer,
            accept_stale_floor,
        } => {
            let local = GitRepository::resolve(repo.as_deref())?
                .context("recover needs a Git repository; run it inside one or pass --repo")?;
            let target = Target::resolve(&target, key, Some(&local))?;
            let options = RecoveryOptions {
                publish,
                base: base.as_deref(),
                discard_newer,
                accept_stale_floor,
            };
            let report =
                with_repository!(&target, |repository| repository.recover(&local, options)?);
            print_recovery_report(&report);
        }
    }
    Ok(())
}

fn default_key_path(repository_root: &str) -> Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            std::env::var_os("HOME").context("HOME is unset and XDG_CONFIG_HOME is unset")?,
        )
        .join(".config"),
    };
    let directory = config_home.join("git-e2ee/keys");
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("create {}", directory.display()))?;
    Ok(directory.join(format!("{repository_root}.json")))
}

fn default_owner_label() -> String {
    Process::new("hostname")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|hostname| hostname.trim().to_owned())
        .filter(|hostname| validate_device_label(hostname).is_ok())
        .unwrap_or_else(|| "owner".to_owned())
}

fn git_config(repository: &GitRepository, key: &str, path: bool) -> Result<Option<String>> {
    let mut command = repository.git();
    command.arg("config");
    if path {
        command.arg("--path");
    }
    let output = command.args(["--get", key]).output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else {
        Ok(None)
    }
}

fn run_git(repository: &GitRepository, args: &[&str]) -> Result<()> {
    let output = repository.git().args(args).output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn print_recovery_report(report: &RecoveryReport) {
    println!("{}", format_recovery_report(report));
}

fn format_recovery_report(report: &RecoveryReport) -> String {
    let mut lines = vec![format!(
        "storage head: {} ({})",
        report.classification.name(),
        report.reason
    )];
    if let Some(head) = &report.head_id {
        lines.push(format!("head manifest: {head}"));
    }
    if let Some(signer) = &report.claimed_signer {
        if report.classification.name() == "invalid" {
            lines.push(format!("claimed signer (signature not verified): {signer}"));
        } else {
            lines.push(format!("verified signer: {signer}"));
        }
    }
    if let (Some(floor), Some(generation)) = (&report.floor_id, report.floor_generation) {
        lines.push(format!(
            "continuity floor: {floor} (generation {generation})"
        ));
    } else {
        lines.push(
            "continuity floor: unavailable; freshness and fork identity are unverified".to_owned(),
        );
    }
    for candidate in &report.candidates {
        let outer = candidate
            .outer_commit
            .as_deref()
            .unwrap_or("directory backend");
        lines.push(format!(
            "candidate: {} generation={} outer={} verified-signer={}",
            candidate.manifest_id, candidate.generation, outer, candidate.verified_signer
        ));
    }
    for replay in &report.replays {
        lines.push(format!("replay: {replay}"));
    }
    if report.conflict {
        lines.push("conflict: authenticated descendants form a fork".to_owned());
    }
    if let Some(base) = &report.default_base {
        lines.push(format!("default base: {base}"));
    }
    if let Some(warning) = &report.warning {
        lines.push(format!("warning: {warning}"));
    }
    if let Some(blocked) = &report.blocked_reason {
        lines.push(format!("recovery refused: {blocked}"));
    }
    if let Some(manifest) = &report.published_manifest {
        lines.push(format!("published recovery manifest: {manifest}"));
    }
    lines.join("\n")
}

fn role_name(roles: &DeviceRoles) -> &'static str {
    if roles.administrator {
        "admin"
    } else if roles.writer {
        "write"
    } else if roles.reader {
        "read"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, format_recovery_report};
    use git_remote_e2ee::repository::{RecoveryClass, RecoveryReport};

    #[test]
    fn recover_cli_defaults_to_report_and_accepts_explicit_publication_flags() {
        let cli = Cli::try_parse_from([
            "git-e2ee",
            "recover",
            "e2ee::dir:/tmp/storage",
            "--key",
            "/tmp/key.json",
        ])
        .unwrap();
        match cli.command {
            Command::Recover {
                publish,
                accept_stale_floor,
                ..
            } => {
                assert!(!publish);
                assert!(!accept_stale_floor);
            }
            _ => panic!("parsed a different command"),
        }

        assert!(
            Cli::try_parse_from(["git-e2ee", "recover", "origin", "--discard-newer",]).is_err()
        );
        let cli = Cli::try_parse_from([
            "git-e2ee",
            "recover",
            "e2ee::https://host/carrier.git",
            "--publish",
            "--base",
            "deadbeef",
            "--discard-newer",
            "--accept-stale-floor",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Recover { publish: true, .. }
        ));
    }

    #[test]
    fn invalid_signer_output_is_labeled_as_a_claim() {
        let report = RecoveryReport {
            classification: RecoveryClass::Invalid,
            reason: "signature verification failed".to_owned(),
            head_id: Some("head-id".to_owned()),
            claimed_signer: Some("device-id".to_owned()),
            floor_id: None,
            floor_generation: None,
            candidates: Vec::new(),
            default_base: None,
            replays: Vec::new(),
            conflict: false,
            freshness_unverified: true,
            warning: None,
            blocked_reason: None,
            published_manifest: None,
        };
        let output = format_recovery_report(&report);
        assert!(output.contains("claimed signer (signature not verified): device-id"));
    }
}
