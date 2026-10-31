//! Bounded directory-metadata cache for path canonicalization.
//!
//! Only successful intermediate-directory lookups are cached. Final paths,
//! symlinks, lookup failures and dynamic /proc, /sys and /dev paths always
//! reach the kernel. Entries expire 100 ms after insertion, without renewal
//! on a hit. Guest namespace/permission mutations invalidate the cache at
//! entry and exit; unrelated host processes can leave it stale for that TTL.
//! Set BOXKERNEL_NO_PATH_CACHE to disable this optimization.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::sysnum::Sysnum;

const MAX_DIRECTORIES: usize = 4096;
const MAX_AGE: Duration = Duration::from_millis(100);

struct Entry {
    stat: libc::stat,
    inserted: Instant,
}

#[derive(Default)]
struct DirectoryCache {
    entries: HashMap<Vec<u8>, Entry>,
}

impl DirectoryCache {
    fn stat(&mut self, path: &CStr, now: Instant) -> Result<libc::stat, i32> {
        let key = path.to_bytes();
        if let Some(entry) = self.entries.get(key) {
            if now.saturating_duration_since(entry.inserted) < MAX_AGE {
                return Ok(entry.stat);
            }
            self.entries.remove(key);
        }
        let stat = crate::sys::lstat(path)?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            // Clearing a full table keeps eviction bounded and avoids an
            // allocation or list update on every hit.
            if self.entries.len() >= MAX_DIRECTORIES {
                self.entries.clear();
            }
            self.entries.insert(
                key.to_vec(),
                Entry {
                    stat,
                    inserted: now,
                },
            );
        }
        Ok(stat)
    }
}

thread_local! {
    static DIRECTORIES: RefCell<DirectoryCache> = RefCell::default();
}

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("BOXKERNEL_NO_PATH_CACHE").is_none())
}

pub(crate) fn is_dynamic_path(path: &[u8]) -> bool {
    [b"/proc".as_slice(), b"/sys", b"/dev"]
        .iter()
        .any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(*prefix)
                    .is_some_and(|p| p.first() == Some(&b'/'))
        })
}

pub(crate) fn lstat(path: &CStr, cacheable: bool) -> Result<libc::stat, i32> {
    if !cacheable || !enabled() || is_dynamic_path(path.to_bytes()) {
        return crate::sys::lstat(path);
    }
    DIRECTORIES.with(|cache| cache.borrow_mut().stat(path, Instant::now()))
}

/// All tracees run on the same event-loop thread. Invalidating this table
/// also invalidates results shared by sibling processes and namespaces.
pub(crate) fn invalidate() {
    DIRECTORIES.with(|cache| cache.borrow_mut().entries.clear());
}

/// Operations that can replace a cached directory or change the metadata
/// fake-root permission handling consumes. Creation is included so chained
/// extension emulations also start from fresh namespace information.
pub(crate) fn may_change_directories(sysnum: Sysnum) -> bool {
    matches!(
        sysnum,
        Sysnum::chmod
            | Sysnum::fchmod
            | Sysnum::fchmodat
            | Sysnum::chown
            | Sysnum::chown32
            | Sysnum::fchown
            | Sysnum::fchown32
            | Sysnum::fchownat
            | Sysnum::lchown
            | Sysnum::lchown32
            | Sysnum::mkdir
            | Sysnum::mkdirat
            | Sysnum::rmdir
            | Sysnum::rename
            | Sysnum::renameat
            | Sysnum::renameat2
            | Sysnum::unlink
            | Sysnum::unlinkat
            | Sysnum::symlink
            | Sysnum::symlinkat
            | Sysnum::mount
            | Sysnum::umount
            | Sysnum::umount2
            | Sysnum::pivot_root
            | Sysnum::chroot
            | Sysnum::setns
            | Sysnum::unshare
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directory_hits_expire_without_renewal() {
        let td = TempDir::new("directory-cache");
        let directory = td.dir("directory");
        let path = CString::new(directory.to_str().unwrap()).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cache = DirectoryCache::default();
        let now = Instant::now();
        assert_eq!(cache.stat(&path, now).unwrap().st_mode & 0o777, 0o755);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Hits must not extend the lifetime of an externally stale result.
        assert_eq!(
            cache.stat(&path, now + MAX_AGE / 2).unwrap().st_mode & 0o777,
            0o755
        );
        assert_eq!(
            cache.stat(&path, now + MAX_AGE).unwrap().st_mode & 0o777,
            0o700
        );
    }

    #[test]
    fn invalidation_observes_directory_replaced_by_symlink() {
        let td = TempDir::new("directory-cache-replace");
        let directory = td.dir("directory");
        td.dir("target");
        let path = CString::new(directory.to_str().unwrap()).unwrap();
        let mut cache = DirectoryCache::default();
        let now = Instant::now();
        assert_eq!(
            cache.stat(&path, now).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFDIR
        );
        std::fs::remove_dir(&directory).unwrap();
        td.symlink("target", "directory");
        assert_eq!(
            cache.stat(&path, now).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFDIR
        );
        cache.entries.clear();
        assert_eq!(
            cache.stat(&path, now).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFLNK
        );
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn failures_and_regular_files_are_never_cached() {
        let td = TempDir::new("directory-cache-files");
        let path = CString::new(td.path().join("file").to_str().unwrap()).unwrap();
        let mut cache = DirectoryCache::default();
        let now = Instant::now();
        assert!(matches!(cache.stat(&path, now), Err(libc::ENOENT)));
        td.file("file", b"data");
        assert_eq!(
            cache.stat(&path, now).unwrap().st_mode & libc::S_IFMT,
            libc::S_IFREG
        );
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn dynamic_paths_match_component_boundaries() {
        for path in ["/proc", "/proc/1/fd", "/sys/devices", "/dev/shm"] {
            assert!(is_dynamic_path(path.as_bytes()));
        }
        for path in ["/process", "/system", "/device", "/root/proc", "/usr/lib"] {
            assert!(!is_dynamic_path(path.as_bytes()));
        }
    }

    #[test]
    fn directory_count_is_bounded() {
        let td = TempDir::new("directory-cache-limit");
        let path = CString::new(td.path().to_str().unwrap()).unwrap();
        let stat = crate::sys::lstat(&path).unwrap();
        let now = Instant::now();
        let mut cache = DirectoryCache::default();
        for index in 0..MAX_DIRECTORIES {
            cache.entries.insert(
                format!("/cached-{index}").into_bytes(),
                Entry {
                    stat,
                    inserted: now,
                },
            );
        }
        cache.stat(&path, now).unwrap();
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn namespace_and_permission_changes_require_invalidation() {
        for sysnum in [
            Sysnum::renameat2,
            Sysnum::rmdir,
            Sysnum::unlinkat,
            Sysnum::symlinkat,
            Sysnum::fchmodat,
            Sysnum::mount,
        ] {
            assert!(may_change_directories(sysnum));
        }
        for sysnum in [
            Sysnum::read,
            Sysnum::statx,
            Sysnum::newfstatat,
            Sysnum::openat,
        ] {
            assert!(!may_change_directories(sysnum));
        }
    }
}
