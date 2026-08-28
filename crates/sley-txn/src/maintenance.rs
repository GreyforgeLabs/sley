//! Shared repository-maintenance ownership for transactions, refs, and GC.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

const LOCK_DIRECTORY: &str = "locks";
const MAINTENANCE_LOCK_FILE: &str = "maintenance.lock";

/// Held shared or exclusive maintenance ownership for one exact repository.
///
/// Shared ownership admits cooperating transaction and ref operations.
/// Exclusive ownership excludes them while garbage collection is active.
#[derive(Debug)]
pub struct RepositoryMaintenanceGuard {
    repository_root: PathBuf,
    exclusive: bool,
    _file: File,
}

impl RepositoryMaintenanceGuard {
    /// Returns the exact canonical repository root covered by this guard.
    #[must_use]
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    /// Returns whether this guard holds exclusive maintenance ownership.
    #[must_use]
    pub const fn is_exclusive(&self) -> bool {
        self.exclusive
    }

    /// Returns whether this guard covers the supplied repository root.
    #[must_use]
    pub fn covers(&self, root: &Path) -> bool {
        canonical_real_directory(root).is_ok_and(|candidate| candidate == self.repository_root)
    }
}

/// Creates the durable maintenance-lock boundary when absent.
///
/// This function creates only `locks/maintenance.lock`; callers acquire the
/// resulting file before any repository object, transaction, ref, or recovery
/// mutation.
///
/// # Errors
///
/// Returns an I/O error for a missing/invalid root, a symlink or non-directory
/// lock component, a non-regular lock file, or a persistence failure.
pub fn initialize_repository_maintenance(root: &Path) -> io::Result<()> {
    initialize_repository_maintenance_inner(root, false)
}

fn initialize_repository_maintenance_inner(
    root: &Path,
    fail_after_lock_create_before_sync: bool,
) -> io::Result<()> {
    require_real_directory(root)?;
    let lock_directory = root.join(LOCK_DIRECTORY);
    match fs::create_dir(&lock_directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    require_real_directory(&lock_directory)?;
    sync_directory(root)?;
    let lock_path = lock_directory.join(MAINTENANCE_LOCK_FILE);
    let (file, created) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            require_regular_file(&lock_path)?;
            (
                OpenOptions::new().read(true).write(true).open(&lock_path)?,
                false,
            )
        }
        Err(error) => return Err(error),
    };
    if created && fail_after_lock_create_before_sync {
        return Err(io::Error::other(
            "injected maintenance-lock create-before-sync failure",
        ));
    }
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("maintenance lock is not a regular file"));
    }
    file.sync_all()?;
    sync_directory(&lock_directory)?;
    Ok(())
}

/// Acquires shared maintenance ownership using an existing lock boundary.
///
/// # Errors
///
/// Returns an I/O error when the boundary is absent/invalid or locking fails.
pub fn acquire_shared_repository_maintenance(
    root: &Path,
) -> io::Result<RepositoryMaintenanceGuard> {
    acquire_repository_maintenance(root, false)
}

/// Acquires exclusive maintenance ownership using an existing lock boundary.
///
/// # Errors
///
/// Returns an I/O error when the boundary is absent/invalid or locking fails.
pub fn acquire_exclusive_repository_maintenance(
    root: &Path,
) -> io::Result<RepositoryMaintenanceGuard> {
    acquire_repository_maintenance(root, true)
}

fn acquire_repository_maintenance(
    root: &Path,
    exclusive: bool,
) -> io::Result<RepositoryMaintenanceGuard> {
    let repository_root = canonical_real_directory(root)?;
    let lock_directory = repository_root.join(LOCK_DIRECTORY);
    require_real_directory(&lock_directory)?;
    let lock_path = lock_directory.join(MAINTENANCE_LOCK_FILE);
    require_regular_file(&lock_path)?;
    let file = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("maintenance lock is not a regular file"));
    }
    if exclusive {
        file.lock()?;
    } else {
        file.lock_shared()?;
    }
    Ok(RepositoryMaintenanceGuard {
        repository_root,
        exclusive,
        _file: file,
    })
}

fn canonical_real_directory(path: &Path) -> io::Result<PathBuf> {
    require_real_directory(path)?;
    fs::canonicalize(path)
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(
            "repository component is not a real directory",
        ));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::other("repository lock is not a regular file"));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sley-maintenance-test-{}-{sequence:016x}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn interrupted_maintenance_lock_creation_is_redurabilized_on_retry() {
        let root = TempRoot::new();
        assert!(initialize_repository_maintenance_inner(&root.0, true).is_err());
        assert!(root.0.join("locks/maintenance.lock").is_file());

        initialize_repository_maintenance(&root.0).unwrap();
        let guard = acquire_shared_repository_maintenance(&root.0).unwrap();
        assert!(guard.covers(&root.0));
        assert!(!guard.is_exclusive());
    }
}
