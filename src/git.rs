use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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

pub struct PackSource {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: File,
    finished: bool,
}

impl Read for PackSource {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stdout
            .as_mut()
            .expect("pack source stdout is available")
            .read(buffer)
    }
}

impl PackSource {
    pub fn finish(mut self) -> Result<()> {
        self.stdout.take();
        let status = self.child.wait()?;
        self.finished = true;
        if !status.success() {
            bail!(
                "git pack-objects failed: {}",
                read_process_error(&mut self.stderr)
            )
        }
        Ok(())
    }
}

impl Drop for PackSource {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn start_incremental_pack(
    repo: &Path,
    new_refs: &BTreeMap<String, String>,
    old_refs: &BTreeMap<String, String>,
) -> Result<PackSource> {
    let stderr = tempfile::tempfile().context("create pack-objects stderr file")?;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr.try_clone()?))
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
    child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .context("open git pack-objects stdout")?;
    Ok(PackSource {
        child,
        stdout: Some(stdout),
        stderr,
        finished: false,
    })
}

pub struct PackImporter {
    child: Child,
    stdin: Option<ChildStdin>,
    stderr: File,
    finished: bool,
}

impl Write for PackImporter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stdin
            .as_mut()
            .expect("pack importer stdin is available")
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin
            .as_mut()
            .expect("pack importer stdin is available")
            .flush()
    }
}

impl PackImporter {
    pub fn finish(mut self) -> Result<()> {
        self.stdin.take();
        let status = self.child.wait()?;
        self.finished = true;
        if !status.success() {
            bail!(
                "git index-pack failed: {}",
                read_process_error(&mut self.stderr)
            )
        }
        Ok(())
    }
}

impl Drop for PackImporter {
    fn drop(&mut self) {
        if !self.finished {
            self.stdin.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn start_pack_import(repo: &Path) -> Result<PackImporter> {
    let stderr = tempfile::tempfile().context("create index-pack stderr file")?;
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["index-pack", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr.try_clone()?))
        .spawn()?;
    let stdin = child.stdin.take().context("open git index-pack stdin")?;
    Ok(PackImporter {
        child,
        stdin: Some(stdin),
        stderr,
        finished: false,
    })
}

fn read_process_error(file: &mut File) -> String {
    use std::io::Seek;

    let _ = file.rewind();
    let mut message = String::new();
    let _ = file.read_to_string(&mut message);
    message.trim().to_owned()
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
