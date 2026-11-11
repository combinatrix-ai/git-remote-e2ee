use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use git_remote_e2ee::continuity::default_state_dir;
use git_remote_e2ee::crypto::KeyFile;
use git_remote_e2ee::gitcmd::GitRepository;
use git_remote_e2ee::repository::{
    EncryptedRepository, PushMode, PushRejection, ReadOnlyDevice, RefChange, RefOutcome, RefPush,
};
use git_remote_e2ee::storage::{CasConflict, FilesystemStorage, GitStorage, Storage};
use git_remote_e2ee::url::{
    StorageUrl, is_control_or_invisible, redact_carrier_address, safe_diagnostic,
    safe_diagnostic_with_args,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("e2ee: {}", safe_diagnostic(&format!("{error:#}")));
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

    let local = GitRepository::from_environment()?
        .context("the e2ee remote helper must run inside a Git repository")?;
    let state_dir = default_state_dir()?;
    let key_path = configured_key_path(&local, &remote_name)?;
    let key = KeyFile::read(&key_path)?;
    let storage = StorageUrl::parse(&url)?;
    if matches!(&storage, StorageUrl::TrustedLocalGit(_)) {
        let passed = format!("e2ee::{}", url.strip_prefix("e2ee::").unwrap_or(&url));
        let chosen = if remote_name.starts_with("e2ee::trusted-local:") {
            remote_name.clone()
        } else {
            configured_local_value(&local, &format!("remote.{remote_name}.url"))?
                .context("trusted-local carrier requires a configured remote URL")?
        };
        if chosen != passed {
            bail!("trusted-local carrier URL was rewritten before reaching the helper")
        }
    }
    persist_absolute_url(&local, &remote_name, &url, &storage)?;
    match storage {
        StorageUrl::Directory(path) => run_protocol(
            EncryptedRepository::new(FilesystemStorage::new(path), key, state_dir),
            &local,
            remote_name,
        ),
        StorageUrl::Git(remote) => run_protocol(
            EncryptedRepository::new(GitStorage::open(&remote)?, key, state_dir),
            &local,
            remote_name,
        ),
        StorageUrl::TrustedLocalGit(remote) => run_protocol(
            EncryptedRepository::new(GitStorage::open_trusted_local(&remote)?, key, state_dir),
            &local,
            remote_name,
        ),
    }
}

fn run_protocol<S: Storage>(
    repository: EncryptedRepository<S>,
    local_repository: &GitRepository,
    remote_name: String,
) -> Result<()> {
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
                let tracking_name = if remote_name.contains(':')
                    || remote_name.chars().any(is_control_or_invisible)
                {
                    "e2ee"
                } else {
                    remote_name.as_str()
                };
                writeln!(
                    output,
                    "refspec refs/heads/*:refs/remotes/{tracking_name}/*"
                )?;
                writeln!(output, "refspec refs/tags/*:refs/tags/*")?;
                writeln!(output)?;
                output.flush()?;
            }
            "list" | "list for-push" => {
                let manifest = repository.observe_manifest(local_repository)?;
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
                repository.import_packs(local_repository)?;
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
    local_repository: &GitRepository,
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

    let pushes = commands
        .iter()
        .map(String::as_str)
        .map(parse_push)
        .collect::<Result<Vec<_>>>()?;
    let mode = if dry_run {
        PushMode::DryRun
    } else {
        PushMode::Publish
    };
    match repository.push(local_repository, &pushes, mode) {
        Err(error) => {
            for push in &pushes {
                report_push_error(output, remote_name, push.destination, &error)?;
            }
        }
        Ok(outcome) => {
            for (push, result) in pushes.iter().zip(&outcome.refs) {
                match (result, &outcome.publication) {
                    (RefOutcome::Accepted, Ok(_)) => writeln!(output, "ok {}", push.destination)?,
                    (RefOutcome::Rejected(error), _) | (RefOutcome::Accepted, Err(error)) => {
                        report_push_error(output, remote_name, push.destination, error)?
                    }
                }
            }
        }
    }
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn parse_push(command: &str) -> Result<RefPush<'_>> {
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
    let change = if source.is_empty() {
        RefChange::Delete
    } else {
        RefChange::Update { source, force }
    };
    Ok(RefPush {
        destination,
        change,
    })
}

fn report_push_error(
    output: &mut impl Write,
    remote_name: &str,
    destination: &str,
    error: &anyhow::Error,
) -> Result<()> {
    let destination = safe_diagnostic(destination);
    if error.is::<ReadOnlyDevice>() {
        let message = safe_diagnostic(&format!(
            "this device is read-only for {}; ask an administrator for the write role",
            redact_carrier_address(remote_name)
        ));
        writeln!(output, "error {destination} {message}")?;
        eprintln!("e2ee: {destination}: {message}");
    } else {
        writeln!(
            output,
            "error {destination} {}",
            safe_diagnostic_with_args(&push_status(error), &[remote_name])
        )?;
        eprintln!(
            "e2ee: {destination}: {}",
            safe_diagnostic_with_args(&single_line(error), &[remote_name])
        );
    }
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
    safe_diagnostic(&format!("{error:#}"))
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

fn configured_key_path(local: &GitRepository, remote_name: &str) -> Result<PathBuf> {
    let key = format!("remote.{remote_name}.e2ee-key");
    if let Some(path) = configured_path(local, &key)? {
        return Ok(path);
    }
    if let Some(path) = configured_path(local, "e2ee.key")? {
        let path = std::path::absolute(&path)
            .with_context(|| format!("resolve key path {}", path.display()))?;
        set_local_config(local, &key, &path.to_string_lossy())
            .context("persist clone-time key config")?;
        return Ok(path);
    }
    bail!(
        "missing Git config remote.{}.e2ee-key (or clone-time e2ee.key)",
        redact_carrier_address(remote_name)
    )
}

/// A relative storage path in a clone URL is resolved against the directory
/// `git clone` ran in, which later fetches from inside the clone do not share.
/// Rewrite the remote's URL to the absolute path the first time it is seen.
fn persist_absolute_url(
    local: &GitRepository,
    remote_name: &str,
    url: &str,
    storage: &StorageUrl,
) -> Result<()> {
    let absolute = storage.to_config_string();
    let key = format!("remote.{remote_name}.url");
    let Some(configured) = configured_value(local, &key)? else {
        return Ok(());
    };
    let as_given = format!("e2ee::{}", url.strip_prefix("e2ee::").unwrap_or(url));
    if configured != as_given || configured == absolute {
        return Ok(());
    }
    set_local_config(local, &key, &absolute).context("persist absolute remote URL")
}

fn set_local_config(local: &GitRepository, key: &str, value: &str) -> Result<()> {
    let output = local
        .git()
        .args(["config", "--local", key, value])
        .output()?;
    if !output.status.success() {
        bail!(
            "git config {} failed ({})",
            safe_diagnostic_with_args(key, &[key]),
            output.status
        )
    }
    Ok(())
}

fn configured_value(local: &GitRepository, key: &str) -> Result<Option<String>> {
    let output = local.git().args(["config", "--get", key]).output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else {
        Ok(None)
    }
}

fn configured_local_value(local: &GitRepository, key: &str) -> Result<Option<String>> {
    let output = local
        .git()
        .args(["config", "--local", "--get", key])
        .output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
    } else {
        Ok(None)
    }
}

fn configured_path(local: &GitRepository, key: &str) -> Result<Option<PathBuf>> {
    let output = local
        .git()
        .args(["config", "--path", "--get", key])
        .output()?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().into()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_compare_and_swap_is_reported_as_fetch_first() {
        let error = anyhow::Error::new(CasConflict {
            expected: Some("a".repeat(64)),
            actual: Some("b".repeat(64)),
        })
        .context("publish manifest");
        assert_eq!(push_status(&error), "fetch first");
    }

    #[test]
    fn direct_scp_remote_name_is_redacted_in_push_status() {
        let mut output = Vec::new();
        let remote = "e2ee::alice@host:private-token/repo.git";
        report_push_error(
            &mut output,
            remote,
            "refs/heads/main",
            &ReadOnlyDevice.into(),
        )
        .unwrap();
        let status = String::from_utf8(output).unwrap();
        assert!(status.contains("e2ee:[redacted]"), "{status}");
        assert!(!status.contains("private-token"));
    }

    #[test]
    fn rejected_push_status_escapes_controls_without_extra_protocol_lines() {
        let mut output = Vec::new();
        report_push_error(
            &mut output,
            "origin",
            "refs/heads/bad\n\u{1b}[31m",
            &anyhow::anyhow!("bad\u{1b}]52;c;payload\u{7}"),
        )
        .unwrap();
        let status = String::from_utf8(output).unwrap();
        assert_eq!(status.lines().count(), 1);
        assert!(status.contains("bad\\n\\u{1b}[31m"), "{status}");
        assert!(status.contains("bad\\u{1b}]52;c;payload\\u{7}"), "{status}");
        assert!(!status.contains(['\u{1b}', '\u{7}']));
    }
}
