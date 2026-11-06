//! File helpers: atomic replacement and the directory lock.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};

/// Name of the lock file in the database directory.
pub(crate) const LOCK_FILE: &str = "LOCK";

/// Create `dir` and its parents.
pub(crate) fn create_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| Error::storage("creating a database directory", e))
}

/// Read a whole file, or `None` when it does not exist.
pub(crate) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::storage("reading a database file", e)),
    }
}

/// Replace `path` with `bytes` so that a crash leaves either the old file or
/// the new one, never a mix: write a temporary file, sync it, rename it over
/// `path`, then sync the directory.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let write = || -> io::Result<()> {
        let mut options = OpenOptions::new();
        let _ = options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
    };
    write().map_err(|e| Error::storage("replacing a database file", e))
}

/// Make a rename in `dir` durable. Windows offers no way to open a directory
/// through the standard library; NTFS journals the rename itself.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Make the names in `dir` (files created, renamed, or removed) durable,
/// as [`sync_dir`] does, for a directory another crate wrote.
#[cfg_attr(not(any(feature = "auth", feature = "content")), allow(dead_code))]
pub(crate) fn sync_names(dir: &Path) -> Result<()> {
    sync_dir(dir).map_err(|e| Error::storage("syncing a directory", e))
}

/// Ownership of a database directory. Held for the life of the database;
/// released by the operating system when the process ends, however it ends.
#[derive(Debug)]
pub(crate) struct DirLock {
    _file: File,
    #[cfg_attr(any(nex_file_lock, not(unix)), allow(dead_code))]
    path: PathBuf,
}

impl DirLock {
    /// Take the lock on `dir`, or fail with [`Error::Locked`] when another
    /// owner holds it.
    pub(crate) fn acquire(dir: &Path) -> Result<DirLock> {
        let path = dir.join(LOCK_FILE);
        let file = lock_file(&path)?;
        Ok(DirLock { _file: file, path })
    }
}

/// Rust 1.89 and later: an advisory lock through the standard library
/// (`flock` on Unix, `LockFileEx` on Windows).
#[cfg(nex_file_lock)]
#[allow(clippy::incompatible_msrv)]
fn lock_file(path: &Path) -> Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| Error::storage("opening the lock file", e))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(Error::Locked),
        Err(fs::TryLockError::Error(e)) => {
            return Err(Error::storage("locking the database directory", e));
        }
    }
    write_pid(&mut file).map_err(|e| Error::storage("writing the lock file", e))?;
    Ok(file)
}

/// Windows before Rust 1.89: open the lock file with no sharing, which the
/// system refuses to every other open until this handle closes.
#[cfg(all(not(nex_file_lock), windows))]
fn lock_file(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    /// `ERROR_SHARING_VIOLATION`.
    const SHARING_VIOLATION: i32 = 32;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(SHARING_VIOLATION) {
                Error::Locked
            } else {
                Error::storage("opening the lock file", e)
            }
        })?;
    write_pid(&mut file).map_err(|e| Error::storage("writing the lock file", e))?;
    Ok(file)
}

/// Unix before Rust 1.89: the standard library has no file lock, so the lock
/// file holds the owner's process id. A file naming a live process is held;
/// a process that has ended is detected (through `/proc` on Linux, through
/// `ps` elsewhere) and its lock is taken over. Two processes taking over the
/// same stale lock at the same moment is not excluded; builds with Rust 1.89
/// or later use a real lock instead.
#[cfg(all(not(nex_file_lock), unix))]
fn lock_file(path: &Path) -> Result<File> {
    if let Some(bytes) = read_optional(path)? {
        let pid = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            if process_is_alive(pid) {
                return Err(Error::Locked);
            }
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::storage("opening the lock file", e))?;
    write_pid(&mut file).map_err(|e| Error::storage("writing the lock file", e))?;
    Ok(file)
}

#[cfg(all(not(nex_file_lock), unix))]
fn process_is_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        Path::new("/proc").join(pid.to_string()).exists()
    } else {
        ps_finds(pid)
    }
}

/// True when `ps` lists `pid`, or when `ps` cannot be run: not knowing leaves
/// the directory locked. One process spawn, only at open, and only when a
/// lock file is already there.
#[cfg(all(not(nex_file_lock), unix))]
fn ps_finds(pid: u32) -> bool {
    std::process::Command::new("/bin/ps")
        .arg("-p")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(true, |status| status.success())
}

#[cfg(all(not(nex_file_lock), unix))]
impl Drop for DirLock {
    fn drop(&mut self) {
        // Only the pid-file fallback removes its file, and only when it still
        // names this process.
        if let Ok(Some(bytes)) = read_optional(&self.path) {
            let own = std::process::id().to_string();
            if std::str::from_utf8(&bytes).map(str::trim) == Ok(own.as_str()) {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Record the owner's process id in the lock file, for diagnostics.
fn write_pid(file: &mut File) -> io::Result<()> {
    use std::io::Seek;
    file.set_len(0)?;
    let _ = file.seek(io::SeekFrom::Start(0))?;
    write!(file, "{}", std::process::id())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nex-db-fs-{name}-{}-{}",
            std::process::id(),
            id_forge::ulid::Ulid::new()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_write_atomic_replaces_contents() {
        let dir = temp_dir("atomic");
        let path = dir.join("file");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(read_optional(&path).unwrap().unwrap(), b"two");
        assert!(!path.with_extension("tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_read_optional_missing_is_none() {
        let dir = temp_dir("missing");
        assert!(read_optional(&dir.join("nope")).unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(all(not(nex_file_lock), unix))]
    #[test]
    fn test_ps_finds_live_process_and_not_ended_one() {
        assert!(ps_finds(std::process::id()));
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let pid = child.id();
        let _ = child.wait().unwrap();
        assert!(!ps_finds(pid));
    }

    #[test]
    fn test_acquire_second_owner_is_locked() {
        let dir = temp_dir("lock");
        let first = DirLock::acquire(&dir).unwrap();
        assert!(matches!(DirLock::acquire(&dir), Err(Error::Locked)));
        drop(first);
        let again = DirLock::acquire(&dir).unwrap();
        drop(again);
        fs::remove_dir_all(dir).unwrap();
    }
}
