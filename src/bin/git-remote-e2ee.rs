use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::repository::{EncryptedRepository, PushRejection};
use git_remote_e2ee::storage::{CasConflict, FilesystemStorage, GitStorage, Storage};

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
    let backend = parse_backend_url(&url)?;
    persist_absolute_url(&remote_name, &url, &backend)?;
    match backend {
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
                writeln!(output, "refspec refs/tags/*:refs/tags/*")?;
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
        let result = if source.is_empty() && dry_run {
            repository
                .validate_delete_ref_for_remote(local_repository, remote_name, destination)
                .map(|_| String::new())
        } else if source.is_empty() {
            repository.delete_ref_for_remote(local_repository, remote_name, destination)
        } else if dry_run {
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
            Err(error) => {
                writeln!(output, "error {destination} {}", push_status(&error))?;
                eprintln!("e2ee: {destination}: {}", single_line(&error));
            }
        }
    }
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn push_status(error: &anyhow::Error) -> String {
    if let Some(rejection) = error.downcast_ref::<PushRejection>() {
        return rejection.git_status().to_owned();
    }
    if error.downcast_ref::<CasConflict>().is_some() {
        return "fetch first".to_owned();
    }
    single_line(error)
}

fn single_line(error: &anyhow::Error) -> String {
    format!("{error:#}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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
        let path = std::path::absolute(&path)
            .with_context(|| format!("resolve key path {}", path.display()))?;
        set_local_config(&key, &path.to_string_lossy()).context("persist clone-time key config")?;
        return Ok(path);
    }
    bail!("missing Git config {key} (or clone-time e2ee.key)")
}

/// A relative storage path in a clone URL is resolved against the directory
/// `git clone` ran in, which later fetches from inside the clone do not share.
/// Rewrite the remote's URL to the absolute path the first time it is seen.
fn persist_absolute_url(remote_name: &str, url: &str, backend: &BackendUrl) -> Result<()> {
    let absolute = backend.url();
    let key = format!("remote.{remote_name}.url");
    let Some(configured) = configured_value(&key)? else {
        return Ok(());
    };
    let as_given = format!("e2ee::{}", url.strip_prefix("e2ee::").unwrap_or(url));
    if configured != as_given || configured == absolute {
        return Ok(());
    }
    set_local_config(&key, &absolute).context("persist absolute remote URL")
}

fn set_local_config(key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["config", "--local", key, value])
        .output()?;
    if !output.status.success() {
        bail!(
            "git config {key} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn configured_value(key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--get", key])
        .output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else {
        Ok(None)
    }
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

impl BackendUrl {
    fn url(&self) -> String {
        match self {
            Self::Filesystem(path) => format!("e2ee::{}", path.display()),
            Self::Git(remote) => format!("e2ee::git+{remote}"),
        }
    }
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
        let local = Path::new(remote);
        if local.is_relative() && local.exists() {
            return Ok(BackendUrl::Git(
                std::path::absolute(local)?.to_string_lossy().into_owned(),
            ));
        }
        return Ok(BackendUrl::Git(remote.to_owned()));
    }
    Ok(BackendUrl::Filesystem(std::path::absolute(path)?))
}
