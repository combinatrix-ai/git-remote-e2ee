use std::path::{Path, PathBuf};
use std::process::Command as Process;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use git_remote_e2ee::crypto::{KeyFile, PublicDevice};
use git_remote_e2ee::policy::{DeviceRoles, validate_device_label};
use git_remote_e2ee::repository::{
    EncryptedRepository, RecoveryOptions, RecoveryReport, admin_state_path,
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
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        publish: bool,
        #[arg(long, requires = "publish")]
        base: Option<String>,
        #[arg(long, requires = "publish")]
        discard_newer: bool,
        #[arg(long, requires = "publish")]
        accept_stale_floor: bool,
    },
    /// Push without the remote helper; kept for benchmarks
    #[command(hide = true)]
    Push {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long = "ref")]
        reference: String,
        #[arg(long)]
        force: bool,
    },
    /// Fetch without the remote helper; kept for benchmarks
    #[command(hide = true)]
    Fetch {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "origin")]
        remote_name: String,
    },
}

struct Target {
    storage: StorageUrl,
    key: PathBuf,
}

impl Target {
    fn resolve(target: &str, key: Option<PathBuf>) -> Result<Self> {
        let configured = if target.starts_with("e2ee::") {
            None
        } else {
            git_config(&format!("remote.{target}.url"), false)?
        };
        let (url, configured_key) = match configured {
            Some(url) if url.starts_with("e2ee::") => {
                let key = git_config(&format!("remote.{target}.e2ee-key"), true)?;
                (url, key.map(PathBuf::from))
            }
            Some(url) => bail!("Git remote {target} is not an e2ee:: remote ({url})"),
            None if target.starts_with("e2ee::") || target.contains(['/', ':']) => {
                (target.to_owned(), None)
            }
            None => bail!(
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
        match &target.storage {
            StorageUrl::Directory(path) => {
                let $repository = EncryptedRepository::new(FilesystemStorage::new(path), key);
                $body
            }
            StorageUrl::Git(remote) => {
                let $repository = EncryptedRepository::new(GitStorage::open(remote)?, key);
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
            let in_repository = inside_git_repository()?;
            if in_repository && git_config(&format!("remote.{name}.url"), false)?.is_some() {
                bail!("Git remote {name} already exists; choose another name with --name")
            }
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
                    path
                }
            };
            let target = Target {
                storage,
                key: std::path::absolute(key)?,
            };
            let pin = admin_pin_path(&target.key)?;
            with_repository!(&target, |repository| {
                repository.initialize(&label)?;
                repository.pin_admin_state(&pin)?;
            });
            println!("initialized {}", target.storage);
            if in_repository {
                run_git(&["remote", "add", &name, &target.storage.to_string()])?;
                run_git(&[
                    "config",
                    &format!("remote.{name}.e2ee-key"),
                    &target.key.to_string_lossy(),
                ])?;
                println!("added remote {name}");
            }
        }
        Command::Verify { target, key } => {
            let target = Target::resolve(&target, key)?;
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
            let target = Target::resolve(&target, key)?;
            let pin = admin_pin_path(&target.key)?;
            let public = PublicDevice::read(&device)?;
            let device_id = public.device_id.clone();
            let roles = DeviceRoles::from(role);
            let (manifest, policy) = with_repository!(&target, |repository| {
                repository.add_device(public, &label, roles, &pin)?
            });
            println!("added {device_id} ({label}); manifest {manifest}; policy {policy}");
        }
        Command::DeviceRevoke {
            target,
            device_id,
            key,
        } => {
            let target = Target::resolve(&target, key)?;
            let pin = admin_pin_path(&target.key)?;
            let (manifest, policy) = with_repository!(&target, |repository| {
                repository.revoke_device(&device_id, &pin)?
            });
            println!("revoked {device_id}; manifest {manifest}; policy {policy}");
        }
        Command::DeviceList { target, key } => {
            let target = Target::resolve(&target, key)?;
            let pin = admin_pin_path(&target.key)?;
            let own_id = KeyFile::read(&target.key)?.device_id()?;
            let devices = with_repository!(&target, |repository| repository.list_devices(&pin)?);
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
            let target = Target::resolve(&target, key)?;
            let options = RecoveryOptions {
                publish,
                base: base.as_deref(),
                discard_newer,
                accept_stale_floor,
            };
            let report =
                with_repository!(&target, |repository| repository.recover(&repo, options)?);
            print_recovery_report(&report);
        }
        Command::Push {
            storage,
            key,
            repo,
            reference,
            force,
        } => {
            let repository =
                EncryptedRepository::new(FilesystemStorage::new(storage), KeyFile::read(&key)?);
            println!("{}", repository.push_ref(&repo, &reference, force)?);
        }
        Command::Fetch {
            storage,
            key,
            repo,
            remote_name,
        } => {
            let repository =
                EncryptedRepository::new(FilesystemStorage::new(storage), KeyFile::read(&key)?);
            let manifest = repository.fetch_into(&repo, &remote_name)?;
            println!("fetched generation {}", manifest.generation);
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

fn admin_pin_path(key: &Path) -> Result<PathBuf> {
    admin_state_path(&KeyFile::read(key)?.repository_root)
}

fn inside_git_repository() -> Result<bool> {
    Ok(Process::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()?
        .status
        .success())
}

fn git_config(key: &str, path: bool) -> Result<Option<String>> {
    let mut command = Process::new("git");
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

fn run_git(args: &[&str]) -> Result<()> {
    let output = Process::new("git").args(args).output()?;
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
