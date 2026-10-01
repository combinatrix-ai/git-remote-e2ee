use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use git_remote_e2ee::crypto::{KeyFile, PublicDevice};
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::{EncryptedRepository, RecoveryOptions, RecoveryReport};
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage};

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

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        repository_root: Option<String>,
    },
    DeviceExport {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Init {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    CarrierInit {
        #[arg(long)]
        remote: String,
        #[arg(long)]
        key: PathBuf,
    },
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
    Fetch {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "e2ee")]
        remote_name: String,
    },
    Verify {
        #[arg(long)]
        storage: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    DeviceAdd {
        #[arg(long, conflicts_with = "remote", required_unless_present = "remote")]
        storage: Option<PathBuf>,
        #[arg(long, conflicts_with = "storage", required_unless_present = "storage")]
        remote: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        device: PathBuf,
        #[arg(long, value_enum, default_value = "write")]
        role: DeviceRole,
    },
    DeviceRevoke {
        #[arg(long, conflicts_with = "remote", required_unless_present = "remote")]
        storage: Option<PathBuf>,
        #[arg(long, conflicts_with = "storage", required_unless_present = "storage")]
        remote: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        device_id: String,
    },
    DeviceList {
        #[arg(long, conflicts_with = "remote", required_unless_present = "remote")]
        storage: Option<PathBuf>,
        #[arg(long, conflicts_with = "storage", required_unless_present = "storage")]
        remote: Option<String>,
        #[arg(long)]
        key: PathBuf,
    },
    Recover {
        #[arg(long, conflicts_with = "remote", required_unless_present = "remote")]
        storage: Option<PathBuf>,
        #[arg(long, conflicts_with = "storage", required_unless_present = "storage")]
        remote: Option<String>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long, default_value = "origin")]
        remote_name: String,
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
        Command::Init { storage, key } => {
            let pin = admin_pin_path(&key);
            let repository = open_repository(storage, key)?;
            let head = repository.initialize()?;
            repository.pin_admin_state(&pin)?;
            println!("{head}");
        }
        Command::CarrierInit { remote, key } => {
            let pin = admin_pin_path(&key);
            let repository =
                EncryptedRepository::new(GitStorage::open(&remote)?, KeyFile::read(&key)?);
            let head = repository.initialize()?;
            repository.pin_admin_state(&pin)?;
            println!("{head}");
        }
        Command::Push {
            storage,
            key,
            repo,
            reference,
            force,
        } => {
            let repository = open_repository(storage, key)?;
            println!("{}", repository.push_ref(&repo, &reference, force)?);
        }
        Command::Fetch {
            storage,
            key,
            repo,
            remote_name,
        } => {
            let repository = open_repository(storage, key)?;
            let manifest = repository.fetch_into(&repo, &remote_name)?;
            println!("fetched generation {}", manifest.generation);
        }
        Command::Verify { storage, key } => {
            let repository = open_repository(storage, key)?;
            let manifest = repository.verify()?;
            println!(
                "verified generation {} ({} refs, {} packs)",
                manifest.generation,
                manifest.refs.len(),
                manifest.total_pack_count
            );
        }
        Command::DeviceAdd {
            storage,
            remote,
            key,
            device,
            role,
        } => {
            let pin = admin_pin_path(&key);
            let public = PublicDevice::read(&device)?;
            let device_id = public.device_id.clone();
            let roles = DeviceRoles::from(role);
            let (manifest, policy) = match (storage, remote) {
                (Some(storage), None) => {
                    EncryptedRepository::new(FilesystemStorage::new(storage), KeyFile::read(&key)?)
                        .add_device(public, roles, &pin)?
                }
                (None, Some(remote)) => {
                    EncryptedRepository::new(GitStorage::open(&remote)?, KeyFile::read(&key)?)
                        .add_device(public, roles, &pin)?
                }
                _ => unreachable!("clap requires exactly one backend"),
            };
            println!("added {device_id}; manifest {manifest}; policy {policy}");
        }
        Command::DeviceRevoke {
            storage,
            remote,
            key,
            device_id,
        } => {
            let pin = admin_pin_path(&key);
            let (manifest, policy) = match (storage, remote) {
                (Some(storage), None) => {
                    EncryptedRepository::new(FilesystemStorage::new(storage), KeyFile::read(&key)?)
                        .revoke_device(&device_id, &pin)?
                }
                (None, Some(remote)) => {
                    EncryptedRepository::new(GitStorage::open(&remote)?, KeyFile::read(&key)?)
                        .revoke_device(&device_id, &pin)?
                }
                _ => unreachable!("clap requires exactly one backend"),
            };
            println!("revoked {device_id}; manifest {manifest}; policy {policy}");
        }
        Command::DeviceList {
            storage,
            remote,
            key,
        } => {
            let devices = match (storage, remote) {
                (Some(storage), None) => {
                    EncryptedRepository::new(FilesystemStorage::new(storage), KeyFile::read(&key)?)
                        .list_devices()?
                }
                (None, Some(remote)) => {
                    EncryptedRepository::new(GitStorage::open(&remote)?, KeyFile::read(&key)?)
                        .list_devices()?
                }
                _ => unreachable!("clap requires exactly one backend"),
            };
            for device in devices {
                println!(
                    "{} role={} status={}",
                    device.public.device_id,
                    role_name(&device.roles),
                    if device.active() { "active" } else { "revoked" }
                );
            }
        }
        Command::Recover {
            storage,
            remote,
            key,
            repo,
            remote_name,
            publish,
            base,
            discard_newer,
            accept_stale_floor,
        } => {
            let key = KeyFile::read(&key)?;
            let options = RecoveryOptions {
                publish,
                base: base.as_deref(),
                discard_newer,
                accept_stale_floor,
            };
            let report = match (storage, remote) {
                (Some(storage), None) => EncryptedRepository::new(
                    FilesystemStorage::new(storage),
                    key,
                )
                .recover(&repo, &remote_name, options)?,
                (None, Some(remote)) => EncryptedRepository::new(GitStorage::open(&remote)?, key)
                    .recover(&repo, &remote_name, options)?,
                _ => unreachable!("clap requires exactly one backend"),
            };
            print_recovery_report(&report);
            if publish && let Some(reason) = report.blocked_reason.as_deref() {
                bail!("recovery refused: {reason}")
            }
        }
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

fn admin_pin_path(key: &std::path::Path) -> PathBuf {
    let mut value = key.as_os_str().to_owned();
    value.push(".admin-state.json");
    PathBuf::from(value)
}

fn open_repository(
    storage: PathBuf,
    key: PathBuf,
) -> Result<EncryptedRepository<FilesystemStorage>> {
    Ok(EncryptedRepository::new(
        FilesystemStorage::new(storage),
        KeyFile::read(&key)?,
    ))
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
            "--storage",
            "/tmp/carrier",
            "--key",
            "/tmp/key.json",
        ])
        .unwrap();
        match cli.command {
            Command::Recover {
                publish,
                remote_name,
                accept_stale_floor,
                ..
            } => {
                assert!(!publish);
                assert_eq!(remote_name, "origin");
                assert!(!accept_stale_floor);
            }
            _ => panic!("parsed a different command"),
        }

        assert!(
            Cli::try_parse_from([
                "git-e2ee",
                "recover",
                "--storage",
                "/tmp/carrier",
                "--key",
                "/tmp/key.json",
                "--discard-newer",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "git-e2ee",
            "recover",
            "--remote",
            "carrier.git",
            "--key",
            "key.json",
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
