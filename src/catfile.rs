//! One long-lived `git cat-file` process answering many object queries.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use anyhow::{Context, Result};

use crate::gitcmd::GitRepository;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitObjectType {
    pub(crate) fn parse(name: &[u8]) -> Option<Self> {
        match name {
            b"commit" => Some(Self::Commit),
            b"tree" => Some(Self::Tree),
            b"blob" => Some(Self::Blob),
            b"tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

/// Git's answer for one object. A failed or misbehaving process is an
/// `Err`, never `Missing`.
pub(crate) enum BatchHeader {
    Missing,
    Object {
        id: String,
        kind: GitObjectType,
        size: u64,
    },
}

/// `--batch-check` answers headers only; `--batch` follows each present
/// object's header with its body, which the caller must consume in full
/// (`body()` then `end_body()`) before the next request.
pub(crate) struct CatFile {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    finished: bool,
}

impl CatFile {
    pub(crate) fn batch(repo: &GitRepository) -> Result<Self> {
        Self::spawn(repo, "--batch")
    }

    pub(crate) fn batch_check(repo: &GitRepository) -> Result<Self> {
        Self::spawn(repo, "--batch-check")
    }

    fn spawn(repo: &GitRepository, mode: &str) -> Result<Self> {
        let mut child = repo
            .git()
            .args(["cat-file", mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().context("open git cat-file stdin")?;
        let output = child.stdout.take().context("open git cat-file stdout")?;
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            finished: false,
        })
    }

    pub(crate) fn request(&mut self, object: &str) -> io::Result<BatchHeader> {
        if object.is_empty() || object.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Git object name for git cat-file",
            ));
        }
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::other("git cat-file already finished"))?;
        writeln!(input, "{object}")?;
        input.flush()?;
        let mut header = String::new();
        if self.output.read_line(&mut header)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "git cat-file ended before answering",
            ));
        }
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "git cat-file returned an invalid header",
            )
        };
        let fields: Vec<_> = header.split_ascii_whitespace().collect();
        match fields[..] {
            [_, "missing"] => Ok(BatchHeader::Missing),
            [id, kind, size] => Ok(BatchHeader::Object {
                id: id.to_owned(),
                kind: GitObjectType::parse(kind.as_bytes()).ok_or_else(invalid)?,
                size: size.parse().map_err(|_| invalid())?,
            }),
            _ => Err(invalid()),
        }
    }

    /// The body of the object a `--batch` request just answered.
    pub(crate) fn body(&mut self) -> &mut impl Read {
        &mut self.output
    }

    /// Consumes the newline git writes after each object body.
    pub(crate) fn end_body(&mut self) -> io::Result<()> {
        let mut trailer = [0_u8; 1];
        self.output.read_exact(&mut trailer)?;
        if trailer[0] != b'\n' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "git cat-file returned a malformed object trailer",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.input.take();
        let status = self.child.wait()?;
        self.finished = true;
        if !status.success() {
            return Err(io::Error::other("git cat-file failed"));
        }
        Ok(())
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        if !self.finished {
            self.input.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
