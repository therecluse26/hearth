//! Filesystem abstraction for testable storage I/O.
//!
//! The [`Fs`] trait abstracts synchronous filesystem operations used by WAL
//! and SST layers. Production code uses [`RealFs`], which delegates directly
//! to `std::fs`. The simulation crate provides a `FaultFs` implementation
//! that can inject I/O failures at controlled points for crash-recovery
//! testing.

use std::io;
use std::path::Path;

/// A file handle returned by [`Fs::open`] or [`Fs::create`].
///
/// Mirrors the subset of `std::fs::File` operations used by the storage engine.
pub trait FsFile: Send + Sync {
    /// Writes the entire buffer to the file.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;

    /// Reads the entire file contents into a buffer.
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize>;

    /// Flushes and syncs the file to durable storage.
    fn sync_all(&self) -> io::Result<()>;

    /// Seeks to a position in the file.
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64>;

    /// Sets the length of the file (truncate or extend).
    fn set_len(&self, size: u64) -> io::Result<()>;
}

/// Filesystem abstraction for dependency injection.
///
/// All synchronous filesystem operations used by the storage engine go
/// through this trait. Production uses [`RealFs`]; simulation tests use
/// `FaultFs` for deterministic fault injection.
pub trait Fs: Send + Sync {
    /// Opens an existing file for reading and appending.
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Creates a new file (or truncates an existing one) for writing.
    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Opens an existing file for reading only.
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>>;

    /// Reads the entire contents of a file into a byte vector.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Writes data to a file, creating it if needed, truncating if it exists.
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()>;

    /// Creates a directory and all parent directories.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Lists entries in a directory.
    fn read_dir(&self, path: &Path) -> io::Result<Vec<std::path::PathBuf>>;

    /// Removes a file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Renames a file.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
}

/// Production filesystem implementation delegating to `std::fs`.
#[derive(Debug, Clone)]
pub struct RealFs;

/// Wrapper around `std::fs::File` implementing [`FsFile`].
pub struct RealFsFile(std::fs::File);

impl FsFile for RealFsFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(&mut self.0, buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        io::Read::read_to_end(&mut self.0, buf)
    }

    fn sync_all(&self) -> io::Result<()> {
        self.0.sync_all()
    }

    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut self.0, pos)
    }

    fn set_len(&self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }
}

impl Fs for RealFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        Ok(Box::new(RealFsFile(file)))
    }

    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::File::create(path)?; // lgtm[rust/path-injection]
        Ok(Box::new(RealFsFile(file)))
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let file = std::fs::File::open(path)?;
        Ok(Box::new(RealFsFile(file)))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        std::fs::write(path, data)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<std::path::PathBuf>> {
        let entries = std::fs::read_dir(path)? // lgtm[rust/path-injection]
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .collect();
        Ok(entries)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
}
