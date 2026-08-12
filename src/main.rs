use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use git_remote_e2ee::crypto::KeyFile;
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { output } => {
            let key = KeyFile::generate();
            key.write_new(&output)?;
            println!("created {}", output.display());
        }
        Command::Init { storage, key } => {
            let repository = open_repository(storage, key)?;
            println!("{}", repository.initialize()?);
        }
        Command::CarrierInit { remote, key } => {
            let repository =
                EncryptedRepository::new(GitStorage::open(&remote)?, KeyFile::read(&key)?);
            println!("{}", repository.initialize()?);
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
    }
    Ok(())
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
