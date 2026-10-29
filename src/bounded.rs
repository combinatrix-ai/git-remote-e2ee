//! The one way to open a file that untrusted storage controls. Every
//! directory-backend read goes through `open_regular`, so the file-type check
//! happens on the opened handle and size limits apply before any allocation.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(crate) enum Opened {
    Absent,
    /// A regular file, with its length at open time.
    Regular(File, u64),
    /// A symbolic link, FIFO, socket, device, or directory.
    NotRegular,
}

pub(crate) enum Bounded {
    Absent,
    Within(Vec<u8>),
    /// A regular file longer than the limit; its contents were not read.
    Oversized,
    NotRegular,
}

/// Opens `path` for reading without following a final symbolic link and
/// without blocking on a FIFO, then requires a regular file.
pub(crate) fn open_regular(path: &Path) -> io::Result<Opened> {
    let file = match open_no_follow(path)? {
        Raw::Absent => return Ok(Opened::Absent),
        Raw::Refused => return Ok(Opened::NotRegular),
        Raw::Open(file) => file,
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(Opened::NotRegular);
    }
    clear_nonblocking(&file)?;
    Ok(Opened::Regular(file, metadata.len()))
}

/// Reads a regular file of at most `limit` bytes, rejecting a longer one by
/// its length before reading and again if it grew after opening.
pub(crate) fn read_regular_bounded(path: &Path, limit: u64) -> io::Result<Bounded> {
    let (file, length) = match open_regular(path)? {
        Opened::Absent => return Ok(Bounded::Absent),
        Opened::NotRegular => return Ok(Bounded::NotRegular),
        Opened::Regular(file, length) => (file, length),
    };
    if length > limit {
        return Ok(Bounded::Oversized);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Ok(Bounded::Oversized);
    }
    Ok(Bounded::Within(bytes))
}

enum Raw {
    Absent,
    /// The final component cannot be a regular file.
    #[cfg_attr(not(unix), allow(dead_code))]
    Refused,
    Open(File),
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<Raw> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => Ok(Raw::Open(File::from(fd))),
        Err(Errno::NOENT) => Ok(Raw::Absent),
        // A final symlink (ELOOP) or a socket (ENXIO, EOPNOTSUPP).
        Err(Errno::LOOP | Errno::NXIO | Errno::OPNOTSUPP) => Ok(Raw::Refused),
        Err(error) => Err(error.into()),
    }
}

/// Windows has no FIFOs in the filesystem namespace, but this follows
/// symbolic links: a link to a regular file reads as that file.
#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<Raw> {
    match File::open(path) {
        Ok(file) => Ok(Raw::Open(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Raw::Absent),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn clear_nonblocking(file: &File) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    rustix::fs::fcntl_setfl(file, flags - rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}

#[cfg(not(unix))]
fn clear_nonblocking(_file: &File) -> io::Result<()> {
    Ok(())
}
