use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::EncryptedRepository;
use git_remote_e2ee::storage::{FilesystemStorage, GitStorage, Storage};

fn main() {
    if let Err(error) = run() {
        eprintln!("e2ee: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let remote_name = arguments.next().context("missing remote name")?;
    let url = arguments.next().context("missing remote URL")?;
    if arguments.next().is_some() {
        bail!("unexpected extra argument")
    }

    let key_path = configured_key_path(&remote_name)?;
    let key = KeyFile::read(&key_path)?;
    match parse_backend_url(&url)? {
        BackendUrl::Filesystem(path) => run_protocol(
            EncryptedRepository::new(FilesystemStorage::new(path), key),
            remote_name,
        ),
        BackendUrl::Git(remote) => run_protocol(
            EncryptedRepository::new(GitStorage::open(&remote)?, key),
            remote_name,
        ),
    }
}

fn run_protocol<S: Storage>(repository: EncryptedRepository<S>, remote_name: String) -> Result<()> {
    let local_repository = Path::new(".");
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut dry_run = false;

    while let Some(line) = lines.next() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        match line.as_str() {
            "capabilities" => {
                writeln!(output, "fetch")?;
                writeln!(output, "push")?;
                writeln!(output, "option")?;
                writeln!(output, "refspec refs/heads/*:refs/remotes/{remote_name}/*")?;
                writeln!(output)?;
                output.flush()?;
            }
            "list" | "list for-push" => {
                let manifest = repository.observe_manifest(local_repository, &remote_name)?;
                if manifest.refs.contains_key("refs/heads/main") {
                    writeln!(output, "@refs/heads/main HEAD")?;
                }
                for (reference, object) in manifest.refs {
                    writeln!(output, "{object} {reference}")?;
                }
                writeln!(output)?;
                output.flush()?;
            }
            command if command.starts_with("option ") => {
                let option = command.strip_prefix("option ").expect("matched option");
                match option {
                    "dry-run true" => {
                        dry_run = true;
                        writeln!(output, "ok")?;
                    }
                    "dry-run false" => {
                        dry_run = false;
                        writeln!(output, "ok")?;
                    }
                    option
                        if option.starts_with("verbosity ") || option.starts_with("progress ") =>
                    {
                        writeln!(output, "ok")?;
                    }
                    _ => writeln!(output, "unsupported")?,
                }
                output.flush()?;
            }
            command if command.starts_with("fetch ") => {
                consume_batch(&mut lines, "fetch ")?;
                repository.import_packs(local_repository, &remote_name)?;
                writeln!(output)?;
                output.flush()?;
            }
            command if command.starts_with("push ") => {
                process_push_batch(
                    &repository,
                    local_repository,
                    &remote_name,
                    command,
                    &mut lines,
                    &mut output,
                    dry_run,
                )?;
            }
            other => bail!("unsupported remote-helper command: {other}"),
        }
    }
    Ok(())
}

fn process_push_batch<S: git_remote_e2ee::storage::Storage>(
    repository: &EncryptedRepository<S>,
    local_repository: &Path,
    remote_name: &str,
    first: &str,
    lines: &mut impl Iterator<Item = io::Result<String>>,
    output: &mut impl Write,
    dry_run: bool,
) -> Result<()> {
    let mut commands = vec![first.to_owned()];
    for line in lines {
        let line = line?;
        if line.is_empty() {
            break;
        }
        if !line.starts_with("push ") {
            bail!("unexpected command in push batch: {line}")
        }
        commands.push(line);
    }

    for command in commands {
        let spec = command
            .strip_prefix("push ")
            .expect("validated push command");
        let (force, spec) = match spec.strip_prefix('+') {
            Some(spec) => (true, spec),
            None => (false, spec),
        };
        let (source, destination) = spec
            .split_once(':')
            .context("push refspec must contain ':'")?;
        if source.is_empty() {
            writeln!(output, "error {destination} ref deletion is not supported")?;
            continue;
        }
        let result = if dry_run {
            repository
                .validate_push_update_for_remote(
                    local_repository,
                    remote_name,
                    source,
                    destination,
                    force,
                )
                .map(|_| String::new())
        } else {
            repository.push_update_for_remote(
                local_repository,
                remote_name,
                source,
                destination,
                force,
            )
        };
        match result {
            Ok(_) => writeln!(output, "ok {destination}")?,
            Err(error) => writeln!(output, "error {destination} {error}")?,
        }
    }
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn consume_batch(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    expected_prefix: &str,
) -> Result<()> {
    for line in lines {
        let line = line?;
        if line.is_empty() {
            return Ok(());
        }
        if !line.starts_with(expected_prefix) {
            bail!("unexpected command in batch: {line}")
        }
    }
    Ok(())
}

fn configured_key_path(remote_name: &str) -> Result<PathBuf> {
    let key = format!("remote.{remote_name}.e2ee-key");
    if let Some(path) = configured_path(&key)? {
        return Ok(path);
    }
    if let Some(path) = configured_path("e2ee.key")? {
        let value = path.to_string_lossy();
        let output = Command::new("git")
            .args(["config", "--local", &key, &value])
            .output()?;
        if !output.status.success() {
            bail!(
                "persist clone-time key config failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
        return Ok(path);
    }
    bail!("missing Git config {key} (or clone-time e2ee.key)")
}

fn configured_path(key: &str) -> Result<Option<PathBuf>> {
    let output = Command::new("git")
        .args(["config", "--path", "--get", key])
        .output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().into()))
    } else {
        Ok(None)
    }
}

enum BackendUrl {
    Filesystem(PathBuf),
    Git(String),
}

fn parse_backend_url(url: &str) -> Result<BackendUrl> {
    let path = url.strip_prefix("e2ee::").unwrap_or(url);
    if path.is_empty() {
        bail!("empty git-remote-e2ee storage URL")
    }
    if let Some(remote) = path.strip_prefix("git+") {
        if remote.is_empty() {
            bail!("empty carrier Git remote")
        }
        return Ok(BackendUrl::Git(remote.to_owned()));
    }
    Ok(BackendUrl::Filesystem(PathBuf::from(path)))
}
