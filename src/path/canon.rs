//! Canonicalization engine — port of path/canon.c.

use crate::fpath::{FixedPath, PathGuard};
use crate::path::binding::substitute_binding;
use crate::path::f2fs::should_skip_file_access_due_to_f2fs_bug;
use crate::path::proc_emul::{Action, readlink_proc};
use crate::path::{Comparison, Finality, Side, compare_paths, join_paths2};
use crate::tracee::Tracee;
use crate::{NAME_MAX, PATH_MAX};

const MAXSYMLINKS: u32 = 32;

/// `next_component()` — extract the next component from `cursor`, skipping
/// leading separators.  Returns (component, finality); `cursor` is advanced
/// past the component and any trailing separators.
fn next_component<'a>(cursor: &mut &'a [u8]) -> Result<(&'a [u8], Finality), i32> {
    while cursor.first() == Some(&b'/') {
        *cursor = &cursor[1..];
    }
    let start = *cursor;
    let mut i = 0;
    while i < start.len() && start[i] != b'/' {
        i += 1;
    }
    if i >= NAME_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    let component = &start[..i];
    *cursor = &start[i..];
    let want_dir = cursor.first() == Some(&b'/');
    while cursor.first() == Some(&b'/') {
        *cursor = &cursor[1..];
    }
    if cursor.is_empty() {
        Ok((
            component,
            if want_dir {
                Finality::Slash
            } else {
                Finality::Normal
            },
        ))
    } else {
        Ok((component, Finality::NotFinal))
    }
}

/// What the lstat() of a component's host path found: `found` is false when
/// it failed, `mode` is its `st_mode` (0 on failure, barring fix-ups).
#[derive(Copy, Clone)]
pub(crate) struct HostStat {
    found: bool,
    mode: libc::mode_t,
}

impl HostStat {
    pub(crate) fn is_link(self) -> bool {
        (self.mode & libc::S_IFMT) == libc::S_IFLNK
    }
}

/// `substitute_binding_stat()` — substitute bindings into `host_path`, then
/// lstat().  A caller that already lstat'ed this very host path passes the
/// outcome as `known` instead of paying for the syscall again.
///
/// The lstat() runs before the HOST_PATH notification so extensions can
/// reuse it: an extension may chmod the component (fake_id0), but that
/// changes neither its type nor whether it can be looked up, which is all
/// this function reads.
fn substitute_binding_stat(
    tracee: &mut Tracee,
    finality: Finality,
    recursion_level: u32,
    guest_path: &FixedPath,
    host_path: &mut FixedPath,
    known: Option<HostStat>,
) -> Result<HostStat, i32> {
    host_path.set(guest_path.as_bytes());
    substitute_binding(tracee, Side::Guest, host_path)?;

    let mut st: Option<libc::stat> = None;
    let mut stat = match known {
        Some(k) => k,
        None if should_skip_file_access_due_to_f2fs_bug(tracee, host_path.as_bytes()) => {
            crate::sys::set_errno(libc::ENOENT);
            HostStat {
                found: false,
                mode: 0,
            }
        }
        None => match crate::path::cache::lstat(
            host_path.as_c_str(),
            tracee.glue_type == 0
                && !finality.is_final()
                && !crate::path::cache::is_dynamic_path(guest_path.as_bytes()),
        ) {
            Ok(v) => {
                st = Some(v);
                HostStat {
                    found: true,
                    mode: v.st_mode,
                }
            }
            Err(_) => HostStat {
                found: false,
                // /linkerconfig exists on Android but cannot be stat'ed.
                mode: if crate::sys::errno() == libc::EACCES
                    && host_path.as_bytes() == b"/linkerconfig"
                {
                    libc::S_IFDIR
                } else {
                    0
                },
            },
        },
    };

    // Don't notify extensions during the initialization of a binding.
    if tracee.glue_type == 0 {
        let status = crate::extension::notify_host_path(
            tracee,
            host_path,
            finality.is_final() && recursion_level == 0,
            st.as_ref(),
        );
        if status < 0 {
            return Err(status);
        }
    }

    // Build the glue between hostfs and guestfs during binding init.
    if !stat.found && tracee.glue_type != 0 {
        stat.mode = crate::path::glue::build_glue(tracee, guest_path, host_path, finality);
    }

    if !finality.is_final()
        && (stat.mode & libc::S_IFMT) != libc::S_IFDIR
        && (stat.mode & libc::S_IFMT) != libc::S_IFLNK
    {
        return Err(if !stat.found {
            -libc::ENOENT
        } else {
            -libc::ENOTDIR
        });
    }

    Ok(stat)
}

/// `canonicalize()` — like realpath(3) in the guest namespace: resolve
/// `user_path` (relative to the seeded `guest_path`, or absolute) into a
/// canonical guest path.  A final symlink is followed only when
/// `deref_final`.
pub fn canonicalize(
    tracee: &mut Tracee,
    user_path: &[u8],
    deref_final: bool,
    guest_path: &mut FixedPath,
    recursion_level: u32,
) -> Result<(), i32> {
    canonicalize_inner(tracee, user_path, deref_final, guest_path, recursion_level).map(|_| ())
}

/// `canonicalize()` proper.  Also returns what the lstat() of the final
/// `guest_path` found, when this call made one, so that the caller
/// resolving a symlink doesn't lstat the same path a second time.
pub(crate) fn canonicalize_inner(
    tracee: &mut Tracee,
    user_path: &[u8],
    deref_final: bool,
    guest_path: &mut FixedPath,
    recursion_level: u32,
) -> Result<Option<HostStat>, i32> {
    let mut symlinks_followed = 0u32;
    // The lstat() outcome for the current value of `guest_path`, if known.
    let mut last: Option<HostStat> = None;

    if recursion_level > MAXSYMLINKS {
        return Err(-libc::ELOOP);
    }
    if guest_path.len() >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    if user_path.first() != Some(&b'/') {
        if guest_path.as_bytes().first() != Some(&b'/') {
            return Err(-libc::EINVAL);
        }
    } else {
        guest_path.set(b"/");
    }

    let mut cursor: &[u8] = user_path;
    let mut finality = Finality::NotFinal;
    // Scratch buffers live across iterations: `set()`/`join_paths2()`
    // overwrite them wholesale, and they come from the scratch pool so the
    // PATH_MAX memset is paid once per process, not per component.
    let mut scratch_path = PathGuard::new();
    let mut host_path = PathGuard::new();
    let mut hp = PathGuard::new();
    while !finality.is_final() {
        let (component, f) = next_component(&mut cursor)?;
        finality = f;

        if component == b"." {
            if finality.is_final() {
                finality = Finality::Dot;
            }
            continue;
        }
        if component == b".." {
            guest_path.pop_component();
            last = None;
            if finality.is_final() {
                finality = Finality::Slash;
            }
            continue;
        }

        join_paths2(&mut scratch_path, guest_path.as_bytes(), component)?;

        let stat = substitute_binding_stat(
            tracee,
            finality,
            recursion_level,
            &scratch_path,
            &mut host_path,
            None,
        )?;

        // Nothing special unless it's a link we must dereference.
        if !stat.is_link() || (finality == Finality::Normal && !deref_final) {
            guest_path.push_component(component)?;
            debug_assert_eq!(guest_path.as_bytes(), scratch_path.as_bytes());
            last = Some(stat);
            continue;
        }

        // It's a link: dereference *and* canonicalize so it can't escape the
        // new root.
        let mut canonicalize_now = false;
        {
            let mut comparison = compare_paths(b"/proc", guest_path.as_bytes());
            let mut alias_base = PathGuard::new();
            let mut aliased = false;
            if comparison != Comparison::PathsAreEqual && comparison != Comparison::Path1IsPrefix {
                // Check whether guest_path aliases /proc via a binding.
                alias_base.set(guest_path.as_bytes());
                let _ = substitute_binding(tracee, Side::Guest, &mut alias_base);
                if alias_base.as_bytes() != guest_path.as_bytes() {
                    comparison = compare_paths(b"/proc", alias_base.as_bytes());
                    aliased = true;
                }
            }

            match comparison {
                Comparison::PathsAreEqual | Comparison::Path1IsPrefix => {
                    let proc_base = if aliased { &alias_base } else { &*guest_path };
                    match readlink_proc(
                        tracee,
                        &mut scratch_path,
                        proc_base,
                        component,
                        comparison,
                    )? {
                        Action::Canonicalize => canonicalize_now = true,
                        Action::DontCanonicalize => {
                            if finality == Finality::Normal {
                                guest_path.set(scratch_path.as_bytes());
                                return Ok(None);
                            }
                            // Otherwise fall through to the real readlink.
                        }
                        Action::Default => {}
                    }
                }
                _ => {}
            }
        }

        if !canonicalize_now {
            // readlink() reports a length with no terminator.
            let r = crate::sys::readlink(host_path.as_c_str(), scratch_path.as_mut_bytes());
            if r < 0 {
                return Err(-crate::sys::errno());
            }
            if r as usize == PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            scratch_path.set_len_terminated(r as usize);

            if tracee.glue_type == 0 {
                let status =
                    crate::extension::notify_symlink_deref(tracee, &host_path, &mut scratch_path);
                if status < 0 {
                    return Err(status);
                }
            }

            crate::path::detranslate_path(tracee, &mut scratch_path, Some(&host_path))?;
        }

        // 'canon': recursively canonicalize the referree, relative to
        // guest_path when not absolute.
        symlinks_followed += 1;
        let referree = canonicalize_inner(
            tracee,
            scratch_path.as_bytes(),
            true,
            guest_path,
            recursion_level + symlinks_followed,
        )?;

        // A non-final canonicalized component must exist and be a directory.
        // The recursion usually just lstat'ed this very path; glue building
        // has side effects, so it always gets a fresh look.
        let known = if tracee.glue_type == 0 {
            referree
        } else {
            None
        };
        last = Some(substitute_binding_stat(
            tracee,
            finality,
            recursion_level,
            guest_path,
            &mut hp,
            known,
        )?);
    }

    if recursion_level == 0 {
        match finality {
            Finality::Normal => {}
            Finality::Slash => guest_path.push_component(b"")?,
            Finality::Dot => guest_path.push_component(b".")?,
            _ => return Err(-libc::EINVAL),
        }
        if finality != Finality::Normal {
            return Ok(None);
        }
    }

    Ok(last)
}

/// `next_component` helper for callers (binding init etc.) that want the
/// final-component of a canonical path.
pub fn basename_component(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && path[start - 1] != b'/' {
        start -= 1;
    }
    &path[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, test_tracee};

    fn components(path: &str) -> Vec<(Vec<u8>, Finality)> {
        let mut cursor: &[u8] = path.as_bytes();
        let mut out = Vec::new();
        loop {
            match next_component(&mut cursor) {
                Ok((c, f)) => {
                    let done = f.is_final();
                    out.push((c.to_vec(), f));
                    if done {
                        break;
                    }
                }
                Err(e) => panic!("next_component({path:?}) -> {e}"),
            }
        }
        out
    }

    #[test]
    fn next_component_splits_and_marks_finality() {
        assert_eq!(
            components("/a/b/c"),
            vec![
                (b"a".to_vec(), Finality::NotFinal),
                (b"b".to_vec(), Finality::NotFinal),
                (b"c".to_vec(), Finality::Normal),
            ]
        );
        // Trailing slash => Slash finality on the last component.
        assert_eq!(
            components("/a/b/"),
            vec![
                (b"a".to_vec(), Finality::NotFinal),
                (b"b".to_vec(), Finality::Slash),
            ]
        );
        // Repeated separators collapse.
        assert_eq!(
            components("//a///b"),
            vec![
                (b"a".to_vec(), Finality::NotFinal),
                (b"b".to_vec(), Finality::Normal),
            ]
        );
        // Root alone yields an empty, Normal-final component.
        assert_eq!(components("/"), vec![(b"".to_vec(), Finality::Normal)]);
        assert_eq!(components(""), vec![(b"".to_vec(), Finality::Normal)]);
    }

    #[test]
    fn next_component_rejects_overlong_names() {
        let long = vec![b'x'; NAME_MAX];
        let mut cursor: &[u8] = &long;
        assert_eq!(next_component(&mut cursor), Err(-libc::ENAMETOOLONG));
        let ok = vec![b'x'; NAME_MAX - 1];
        let mut cursor: &[u8] = &ok;
        assert!(next_component(&mut cursor).is_ok());
    }

    #[test]
    fn basename_component_extracts_last() {
        assert_eq!(basename_component(b"/a/b/c"), b"c");
        assert_eq!(basename_component(b"/a/b/c/"), b"c");
        assert_eq!(basename_component(b"/"), b"");
        assert_eq!(basename_component(b"/a"), b"a");
        assert_eq!(basename_component(b"rel/file"), b"file");
        assert_eq!(basename_component(b""), b"");
        assert_eq!(basename_component(b"//"), b"");
    }

    /// Canonicalize `user_path` in a tracee rooted at `td`.
    fn canon(t: &mut Tracee, user: &str) -> Result<Vec<u8>, i32> {
        let mut out = FixedPath::new();
        canonicalize(t, user.as_bytes(), true, &mut out, 0).map(|()| out.as_bytes().to_vec())
    }

    #[test]
    fn canonicalize_basic_and_dotdot() {
        let td = TempDir::new("canon");
        td.dir("a/b");
        td.file("a/f", b"");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        // Guest "/" maps to the fixture root; canonicalize emits guest paths.
        assert_eq!(canon(&mut t, "/a/b"), Ok(b"/a/b".to_vec()));
        assert_eq!(canon(&mut t, "/a/b/../../a/f"), Ok(b"/a/f".to_vec()));
        // .. at root clamps to root.
        assert_eq!(canon(&mut t, "/../.."), Ok(b"/".to_vec()));
        assert_eq!(canon(&mut t, "/a/./b"), Ok(b"/a/b".to_vec()));
        assert_eq!(canon(&mut t, "/"), Ok(b"/".to_vec()));
    }

    #[test]
    fn canonicalize_allows_missing_final() {
        let td = TempDir::new("canon");
        td.dir("a");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        // A missing *final* component is fine (like realpath -m).
        assert_eq!(canon(&mut t, "/a/nope"), Ok(b"/a/nope".to_vec()));
        // A missing intermediate is ENOENT.
        assert_eq!(canon(&mut t, "/nope/deeper"), Err(-libc::ENOENT));
    }

    #[test]
    fn canonicalize_enotdir_for_file_prefix() {
        let td = TempDir::new("canon");
        td.file("f", b"x");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/f/sub"), Err(-libc::ENOTDIR));
    }

    #[test]
    fn canonicalize_symlink_absolute_within_root() {
        let td = TempDir::new("canon");
        td.dir("real");
        td.file("real/f", b"x");
        // Absolute symlink targets are interpreted inside the guest root.
        td.symlink("/real", "link");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/link/f"), Ok(b"/real/f".to_vec()));
    }

    #[test]
    fn canonicalize_symlink_relative() {
        let td = TempDir::new("canon");
        td.dir("a");
        td.dir("b");
        td.file("b/f", b"x");
        td.symlink("../b/f", "a/link");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/a/link"), Ok(b"/b/f".to_vec()));
    }

    #[test]
    fn canonicalize_symlink_cannot_escape_root() {
        let td = TempDir::new("canon");
        td.dir("in/deep");
        // Exists only inside the guest rootfs — the host has no
        // /etc/proot-test-marker, so resolution must be guest-contained.
        td.file("etc/proot-test-marker", b"x");
        // Relative escape attempt climbing above the guest root.
        td.symlink("../../../etc/proot-test-marker", "in/deep/esc");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(
            canon(&mut t, "/in/deep/esc"),
            Ok(b"/etc/proot-test-marker".to_vec())
        );
    }

    #[test]
    fn canonicalize_symlink_loop() {
        let td = TempDir::new("canon");
        td.symlink("/x", "x");
        td.symlink("/x", "y"); // /x -> /x forever
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/x"), Err(-libc::ELOOP));
    }

    #[test]
    fn canonicalize_deref_final_flag() {
        let td = TempDir::new("canon");
        td.file("real", b"x");
        td.symlink("real", "lnk");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        // deref_final = false keeps the final link literal.
        let mut out = FixedPath::new();
        canonicalize(&mut t, b"/lnk", false, &mut out, 0).unwrap();
        assert_eq!(out.as_bytes(), b"/lnk");
        // Intermediate links are always dereferenced.
        td.symlink("real", "dir/../lnk2");
        let mut out = FixedPath::new();
        canonicalize(&mut t, b"/lnk2", false, &mut out, 0).unwrap();
        assert_eq!(out.as_bytes(), b"/lnk2");
    }

    #[test]
    fn canonicalize_trailing_slash_and_dot_finality() {
        let td = TempDir::new("canon");
        td.dir("d");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/d/"), Ok(b"/d/".to_vec()));
        assert_eq!(canon(&mut t, "/d/."), Ok(b"/d/.".to_vec()));
    }

    #[test]
    fn canonicalize_relative_rejects_without_base() {
        let td = TempDir::new("canon");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        // Relative user_path with an empty guest_path seed -> EINVAL.
        let mut out = FixedPath::new();
        assert_eq!(
            canonicalize(&mut t, b"rel", true, &mut out, 0),
            Err(-libc::EINVAL)
        );
    }

    #[test]
    fn canonicalize_relative_uses_seeded_base() {
        let td = TempDir::new("canon");
        td.dir("base/sub");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        let mut out = FixedPath::from_bytes(b"/base");
        canonicalize(&mut t, b"sub", true, &mut out, 0).unwrap();
        assert_eq!(out.as_bytes(), b"/base/sub");
    }

    #[test]
    fn canonicalize_glue_for_missing_dir_component() {
        // During binding init (glue_type set), a missing intermediate
        // directory under a *bound* prefix doesn't fail — the glue layer
        // fakes it.  Covered here at the boundary: glue_type=0 must fail.
        let td = TempDir::new("canon");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(canon(&mut t, "/gone/deeper"), Err(-libc::ENOENT));
    }
}
