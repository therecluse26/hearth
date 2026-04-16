//! Deterministic simulation tests for Hearth storage and identity engines.
//!
//! Uses `madsim` for deterministic scheduling and seed-based reproducibility.
//! Uses `FaultFs` (an implementation of Hearth's [`Fs`] trait) for controlled
//! I/O fault injection during crash-recovery tests.
//!
//! # Oracle Traits
//!
//! Each oracle defines the invariants that MUST hold after crash recovery:
//!
//! - [`WalOracle`]: All committed WAL entries survive; no partial entries.
//! - [`SstOracle`]: Recovery after crash during flush/compaction produces valid state.
//! - [`TieredOracle`]: Tier transitions preserve all data.
//! - [`SessionOracle`]: No committed session is lost after crash recovery.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hearth::storage::fs::{Fs, FsFile};

/// Oracle invariant: after crash recovery, all committed WAL entries survive.
/// No partial entries appear in the recovered log.
pub trait WalOracle {
    /// Verifies that the recovered entry set matches the expected committed set.
    fn verify_recovery(&self, committed: &[Vec<u8>], recovered: &[Vec<u8>]) -> bool;
}

/// Oracle invariant: after crash during flush/compaction, recovery from
/// WAL + valid SSTs produces correct state.
pub trait SstOracle {
    /// Verifies that all keys present before the crash are recoverable.
    fn verify_data_integrity(&self, expected_keys: &[Vec<u8>], recovered_keys: &[Vec<u8>]) -> bool;
}

/// Oracle invariant: tier transitions (hot ↔ cold) preserve all data.
/// No entries are lost during promotion or eviction.
pub trait TieredOracle {
    /// Verifies that all non-evicted entries remain accessible.
    fn verify_tier_consistency(&self, promoted: usize, accessible: usize) -> bool;
}

/// Oracle invariant: no committed session is lost after crash recovery.
pub trait SessionOracle {
    /// Verifies that all sessions created before the crash are recoverable.
    fn verify_sessions(&self, created: usize, recovered: usize) -> bool;
}

// ─── FaultFs: Deterministic fault injection filesystem ───

/// Controls when and how the `FaultFs` injects I/O failures.
#[derive(Debug, Clone)]
pub struct FaultConfig {
    /// If true, the next write operation will fail.
    pub fail_next_write: Arc<AtomicBool>,
    /// If true, the next sync operation will fail.
    pub fail_next_sync: Arc<AtomicBool>,
    /// If true, the next read operation will fail.
    pub fail_next_read: Arc<AtomicBool>,
    /// Number of successful writes before injecting failure (0 = immediate).
    pub writes_before_failure: Arc<AtomicU64>,
    /// Counter of writes performed.
    pub write_count: Arc<AtomicU64>,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            fail_next_write: Arc::new(AtomicBool::new(false)),
            fail_next_sync: Arc::new(AtomicBool::new(false)),
            fail_next_read: Arc::new(AtomicBool::new(false)),
            writes_before_failure: Arc::new(AtomicU64::new(u64::MAX)),
            write_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl FaultConfig {
    /// Arms a write failure after `n` successful writes.
    pub fn fail_write_after(&self, n: u64) {
        self.write_count.store(0, Ordering::SeqCst);
        self.writes_before_failure.store(n, Ordering::SeqCst);
    }

    /// Arms an immediate write failure on the next call.
    pub fn arm_write_failure(&self) {
        self.fail_next_write.store(true, Ordering::SeqCst);
    }

    /// Arms an immediate sync failure on the next call.
    pub fn arm_sync_failure(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }

    /// Arms an immediate read failure on the next call.
    pub fn arm_read_failure(&self) {
        self.fail_next_read.store(true, Ordering::SeqCst);
    }

    /// Resets all fault injection flags.
    pub fn reset(&self) {
        self.fail_next_write.store(false, Ordering::SeqCst);
        self.fail_next_sync.store(false, Ordering::SeqCst);
        self.fail_next_read.store(false, Ordering::SeqCst);
        self.writes_before_failure.store(u64::MAX, Ordering::SeqCst);
        self.write_count.store(0, Ordering::SeqCst);
    }
}

/// A filesystem implementation that delegates to the real filesystem but can
/// inject I/O failures at controlled points.
///
/// Used in simulation tests to verify crash-recovery invariants.
pub struct FaultFs {
    /// Fault injection configuration.
    pub config: FaultConfig,
    /// Tracks files that have been partially written (for crash simulation).
    partial_writes: Mutex<HashMap<PathBuf, Vec<u8>>>,
}

impl FaultFs {
    /// Creates a new `FaultFs` with default (no-fault) configuration.
    pub fn new() -> Self {
        Self {
            config: FaultConfig::default(),
            partial_writes: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new `FaultFs` with a specific fault configuration.
    pub fn with_config(config: FaultConfig) -> Self {
        Self {
            config,
            partial_writes: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether a write fault should be injected.
    fn should_fail_write(&self) -> bool {
        if self.config.fail_next_write.swap(false, Ordering::SeqCst) {
            return true;
        }
        let count = self.config.write_count.fetch_add(1, Ordering::SeqCst);
        count >= self.config.writes_before_failure.load(Ordering::SeqCst)
    }
}

impl Default for FaultFs {
    fn default() -> Self {
        Self::new()
    }
}

/// File handle that wraps a real file but can inject faults.
struct FaultFsFile {
    inner: Box<dyn FsFile>,
    config: FaultConfig,
}

impl FsFile for FaultFsFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.config.fail_next_write.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected write fault"));
        }
        let count = self.config.write_count.fetch_add(1, Ordering::SeqCst);
        if count >= self.config.writes_before_failure.load(Ordering::SeqCst) {
            // Write partial data to simulate crash mid-write
            let half = buf.len() / 2;
            if half > 0 {
                self.inner.write_all(&buf[..half])?;
            }
            return Err(io::Error::other("injected write fault (partial)"));
        }
        self.inner.write_all(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        if self.config.fail_next_read.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected read fault"));
        }
        self.inner.read_to_end(buf)
    }

    fn sync_all(&self) -> io::Result<()> {
        if self.config.fail_next_sync.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected sync fault"));
        }
        self.inner.sync_all()
    }

    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }

    fn set_len(&self, size: u64) -> io::Result<()> {
        self.inner.set_len(size)
    }
}

impl Fs for FaultFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let real = hearth::storage::RealFs.open_append(path)?;
        Ok(Box::new(FaultFsFile {
            inner: real,
            config: self.config.clone(),
        }))
    }

    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        let real = hearth::storage::RealFs.create(path)?;
        Ok(Box::new(FaultFsFile {
            inner: real,
            config: self.config.clone(),
        }))
    }

    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        if self.config.fail_next_read.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected read fault"));
        }
        let real = hearth::storage::RealFs.open_read(path)?;
        Ok(Box::new(FaultFsFile {
            inner: real,
            config: self.config.clone(),
        }))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        if self.config.fail_next_read.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected read fault"));
        }
        hearth::storage::RealFs.read(path)
    }

    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        if self.should_fail_write() {
            // Track partial write for crash simulation
            let half = data.len() / 2;
            if half > 0 {
                let mut partial = self
                    .partial_writes
                    .lock()
                    .map_err(|_| io::Error::other("mutex poisoned"))?;
                partial.insert(path.to_path_buf(), data[..half].to_vec());
                // Write partial data to disk
                hearth::storage::RealFs.write(path, &data[..half])?;
            }
            return Err(io::Error::other("injected write fault"));
        }
        hearth::storage::RealFs.write(path, data)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        hearth::storage::RealFs.create_dir_all(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        hearth::storage::RealFs.read_dir(path)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        hearth::storage::RealFs.remove_file(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        hearth::storage::RealFs.rename(from, to)
    }
}

#[cfg(test)]
mod tests;
