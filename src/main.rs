use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use git_remote_e2ee::crypto::{KeyFile, PublicDevice};
use git_remote_e2ee::policy::DeviceRoles;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
        #[arg(long)]
        admin: bool,
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
                manifest.packs.len()
            );
        }
        Command::DeviceAdd {
            storage,
            remote,
            key,
            device,
            admin,
        } => {
            let pin = admin_pin_path(&key);
            let public = PublicDevice::read(&device)?;
            let device_id = public.device_id.clone();
            let roles = if admin {
                DeviceRoles::owner()
            } else {
                DeviceRoles::collaborator()
            };
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
                    "{} reader={} writer={} admin={} status={}",
                    device.public.device_id,
                    device.roles.reader,
                    device.roles.writer,
                    device.roles.administrator,
                    if device.active() { "active" } else { "revoked" }
                );
            }
        }
    }
    Ok(())
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
