use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

pub fn ensure_repository(repo: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--git-dir"])
        .output()?;
    if !output.status.success() {
        bail!("{} is not a Git repository", repo.display())
    }
    Ok(())
}

pub fn resolve_ref(repo: &Path, reference: &str) -> Result<String> {
    git_text(repo, &["rev-parse", "--verify", reference])
}

pub fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("git merge-base failed"),
    }
}

pub fn object_exists(repo: &Path, object: &str) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", object])
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("git cat-file failed"),
    }
}

pub fn create_incremental_pack(
    repo: &Path,
    new_refs: &BTreeMap<String, String>,
    old_refs: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let input = child
            .stdin
            .as_mut()
            .context("open git pack-objects stdin")?;
        for object in new_refs.values() {
            writeln!(input, "{object}")?;
        }
        for object in old_refs.values() {
            writeln!(input, "^{object}")?;
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    if output.stdout.is_empty() {
        bail!("git produced an empty pack")
    }
    Ok(output.stdout)
}

pub fn import_pack(repo: &Path, pack: &[u8]) -> Result<()> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("open git index-pack stdin")?
        .write_all(pack)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git index-pack failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

pub fn ensure_refs_connected(repo: &Path, refs: &BTreeMap<String, String>) -> Result<()> {
    if refs.is_empty() {
        return Ok(());
    }
    for (reference, object) in refs {
        let expression = format!("{object}^{{commit}}");
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "-e", &expression])
            .output()?;
        if !output.status.success() {
            bail!("fetched ref {reference} does not resolve to a complete commit")
        }
    }

    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(["rev-list", "--objects", "--missing=print"]);
    for object in refs.values() {
        command.arg(object);
    }
    let output = command.output()?;
    if !output.status.success() {
        bail!(
            "git connectivity check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    if String::from_utf8(output.stdout)?
        .lines()
        .any(|line| line.starts_with('?'))
    {
        bail!("fetched refs contain missing Git objects")
    }
    Ok(())
}

pub fn update_ref(repo: &Path, reference: &str, object: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["update-ref", reference, object])
        .output()?;
    if !output.status.success() {
        bail!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
