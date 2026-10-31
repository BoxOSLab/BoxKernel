//! ELF auxiliary vectors — port of execve/auxv.c.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, poke_word, read_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg, sizeof_word};

pub const AT_NULL: Word = 0;
pub const AT_IGNORE: Word = 1;
pub const AT_PHENT: Word = 4;
pub const AT_PHNUM: Word = 5;
pub const AT_PAGESZ: Word = 6;
pub const AT_BASE: Word = 7;
pub const AT_FLAGS: Word = 8;
pub const AT_ENTRY: Word = 9;
pub const AT_UID: Word = 11;
pub const AT_EUID: Word = 12;
pub const AT_GID: Word = 13;
pub const AT_EGID: Word = 14;
pub const AT_HWCAP: Word = 16;
pub const AT_CLKTCK: Word = 17;
pub const AT_SECURE: Word = 23;
pub const AT_RANDOM: Word = 25;
pub const AT_EXECFN: Word = 31;
pub const AT_SYSINFO: Word = 32;
pub const AT_SYSINFO_EHDR: Word = 33;

#[derive(Copy, Clone, Default)]
pub struct ElfAuxVector {
    pub atype: Word,
    pub value: Word,
}

/// `get_elf_aux_vectors_address()` — locate the auxv table on the initial
/// stack right after a successful execve (valid only in execve sysexit).
/// Returns 0 on error.
pub fn get_elf_aux_vectors_address(tracee: &Tracee) -> Word {
    get_elf_aux_vectors_address_at(
        tracee,
        peek_reg(tracee, RegVersion::Current, Reg::StackPointer),
    )
}

/// Locate auxv in a saved initial stack after the tracee has started.
fn get_elf_aux_vectors_address_at(tracee: &Tracee, stack_pointer: Word) -> Word {
    // Linux's argv/envp allowance is at most 6 MiB. Leave headroom, but
    // never trust guest-writable argc or an unterminated envp indefinitely.
    const MAX_INITIAL_STACK_BYTES: Word = 16 * 1024 * 1024;
    let w = sizeof_word(tracee) as Word;
    let Some(limit) = stack_pointer.checked_add(MAX_INITIAL_STACK_BYTES) else {
        return 0;
    };
    crate::sys::clear_errno();
    let argc = peek_word(tracee, stack_pointer);
    if crate::sys::errno() != 0 {
        return 0;
    }
    let Some(argv_bytes) = argc.checked_add(2).and_then(|n| n.checked_mul(w)) else {
        return 0;
    };
    if argv_bytes > MAX_INITIAL_STACK_BYTES {
        return 0;
    }
    let Some(mut address) = stack_pointer.checked_add(argv_bytes) else {
        return 0;
    };

    // Scan envp in bounded chunks that never cross a guest page. Only the
    // terminating NULL matters; no environment-string pointer is followed.
    let page_size = crate::sys::page_size() as Word;
    let mut pointers = [0u8; 4096];
    while address < limit {
        let size = (page_size - address % page_size)
            .min(limit - address)
            .min(pointers.len() as Word)
            / w
            * w;
        if size == 0 || read_data(tracee, &mut pointers[..size as usize], address) < 0 {
            return 0;
        }
        for pointer in pointers[..size as usize].chunks_exact(w as usize) {
            // The bounded chunk ensures this addition cannot overflow.
            address += w;
            if pointer.iter().all(|byte| *byte == 0) {
                return address;
            }
        }
    }
    0
}

/// `fetch_elf_aux_vectors()` — read the AT_NULL-terminated vector list.
pub fn fetch_elf_aux_vectors(tracee: &Tracee, address: Word) -> Option<Vec<ElfAuxVector>> {
    // The kernel currently emits fewer than 64 pairs. A corrupt guest
    // table must not cause an unbounded remote-memory walk.
    const MAX_AUXV_ENTRIES: usize = 256;
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    let mut vectors = Vec::new();
    for _ in 0..MAX_AUXV_ENTRIES {
        crate::sys::clear_errno();
        let atype = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address = address.checked_add(w)?;
        if atype == AT_NULL {
            vectors.push(ElfAuxVector {
                atype: AT_NULL,
                value: 0,
            });
            return Some(vectors);
        }
        let value = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address = address.checked_add(w)?;
        vectors.push(ElfAuxVector { atype, value });
    }
    None
}

/// Snapshot the custom loader's corrected vectors on the first proc-auxv
/// open. Reading the regular file then works through dup, pread, readv and
/// close_range without intercepting read syscalls or tracking fd numbers.
pub(crate) fn snapshot_file(tracee: &mut Tracee) -> Result<std::rc::Rc<str>, i32> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(path) = &tracee.auxv_file {
        return Ok(path.clone());
    }
    let address = get_elf_aux_vectors_address_at(tracee, tracee.auxv_stack_pointer);
    if address == 0 {
        return Err(-libc::EIO);
    }
    let vectors = fetch_elf_aux_vectors(tracee, address).ok_or(-libc::EIO)?;
    let path = crate::path::temp::create_temp_file("auxv").ok_or(-libc::EIO)?;
    if crate::execve::exit::fill_file_with_auxv(tracee, &path, &vectors) < 0 {
        return Err(-libc::EIO);
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
        .map_err(|error| -error.raw_os_error().unwrap_or(libc::EIO))?;
    let path: std::rc::Rc<str> = std::rc::Rc::from(path);
    tracee.auxv_file = Some(path.clone());
    Ok(path)
}

/// `push_elf_aux_vectors()` — write the vector list back to `address`.
pub fn push_elf_aux_vectors(tracee: &Tracee, vectors: &[ElfAuxVector], address: Word) -> i32 {
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    for v in vectors
        .iter()
        .chain(std::iter::once(&ElfAuxVector::default()))
    {
        crate::sys::clear_errno();
        poke_word(tracee, address, v.atype);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        poke_word(tracee, address, v.value);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        if v.atype == AT_NULL {
            break;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, fork_child};
    use crate::tracee::mem::poke_word;

    /// Build a fake initial process stack in the arena:
    ///   [argc][argv0][NULL][envp0][NULL][auxv pairs][AT_NULL]
    /// `sp` points at argc.
    fn fake_stack(
        t: &mut Tracee,
        arena: &Arena,
        argc: u64,
        nenvp: u64,
        auxv: &[(u64, u64)],
    ) -> Word {
        let sp = arena.addr() + 0x800;
        let w = 8u64;
        let mut a = sp;
        poke_word(t, a, argc);
        a += w;
        for i in 0..argc {
            poke_word(t, a, 0x1000 + i);
            a += w;
        }
        poke_word(t, a, 0);
        a += w;
        for i in 0..nenvp {
            poke_word(t, a, 0x2000 + i);
            a += w;
        }
        poke_word(t, a, 0);
        a += w;
        let auxv_addr = a;
        for (k, v) in auxv {
            poke_word(t, a, *k);
            a += w;
            poke_word(t, a, *v);
            a += w;
        }
        poke_word(t, a, AT_NULL);
        // Keep everything within one page.
        assert!(a + w < arena.addr() + 0x800 + 4096);
        auxv_addr
    }

    #[test]
    fn auxv_address_lands_after_envp() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let expected = fake_stack(&mut t, &arena, 2, 3, &[(AT_PHENT, 56), (AT_PAGESZ, 4096)]);
        poke_reg_sp(&mut t, arena.addr() + 0x800);
        assert_eq!(get_elf_aux_vectors_address(&t), expected);
    }

    #[test]
    fn auxv_address_zero_argc_and_envp() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let expected = fake_stack(&mut t, &arena, 0, 0, &[(AT_ENTRY, 0x401000)]);
        poke_reg_sp(&mut t, arena.addr() + 0x800);
        assert_eq!(get_elf_aux_vectors_address(&t), expected);
    }

    #[test]
    fn auxv_address_bad_sp_returns_zero() {
        let arena = Arena::new(2);
        let mut child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        child.protect_page(1); // fault the page containing the stack
        poke_reg_sp(&mut t, arena.addr() + 0x1000);
        assert_eq!(get_elf_aux_vectors_address(&t), 0);
    }

    #[test]
    fn fetch_push_auxv_roundtrip() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let auxv_addr = fake_stack(
            &mut t,
            &arena,
            1,
            1,
            &[(AT_PHENT, 56), (AT_PHNUM, 9), (AT_RANDOM, 0xBEEF)],
        );
        let v = fetch_elf_aux_vectors(&t, auxv_addr).unwrap();
        assert_eq!(v.len(), 4); // 3 + terminating AT_NULL
        assert_eq!(v[0].atype, AT_PHENT);
        assert_eq!(v[0].value, 56);
        assert_eq!(v[2].value, 0xBEEF);
        assert_eq!(v[3].atype, AT_NULL);

        // Push a modified list to a different region and fetch it back.
        let dst = arena.addr() + 0x1800;
        assert_eq!(push_elf_aux_vectors(&t, &v, dst), 0);
        let v2 = fetch_elf_aux_vectors(&t, dst).unwrap();
        assert_eq!(v2.len(), 4);
        assert_eq!(v2[2].value, 0xBEEF);
    }

    #[test]
    fn lazy_snapshot_uses_initial_stack_and_is_reused() {
        let arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee();
        let address = fake_stack(
            &mut t,
            &arena,
            1,
            1,
            &[(AT_BASE, 0x4000), (AT_EXECFN, 0xBEEF)],
        );
        t.auxv_stack_pointer = arena.addr() + 0x800;
        // The running program's current SP need not still point at argc.
        poke_reg_sp(&mut t, arena.addr() + 0x1800);
        let first = snapshot_file(&mut t).unwrap();
        let data = std::fs::read(first.as_ref()).unwrap();
        let words: Vec<u64> = data
            .chunks_exact(8)
            .map(|word| u64::from_ne_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words, [AT_BASE, 0x4000, AT_EXECFN, 0xBEEF, AT_NULL, 0]);
        // A cached file is an exec-time view; subsequent opens reuse it.
        poke_word(&t, address + 8, 0x8000);
        let second = snapshot_file(&mut t).unwrap();
        assert!(std::rc::Rc::ptr_eq(&first, &second));
        assert_eq!(std::fs::read(second.as_ref()).unwrap(), data);
    }

    #[test]
    fn lazy_snapshot_rejects_corrupt_argc_and_unterminated_vectors() {
        let arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee();
        let address = fake_stack(&mut t, &arena, 1, 1, &[(AT_BASE, 0x4000)]);
        let initial_sp = arena.addr() + 0x800;
        t.auxv_stack_pointer = initial_sp;
        poke_word(&t, initial_sp, Word::MAX);
        assert!(matches!(snapshot_file(&mut t), Err(error) if error == -libc::EIO));
        poke_word(&t, initial_sp, 1);
        for offset in 0..256 {
            poke_word(&t, address + offset * 16, AT_IGNORE);
            poke_word(&t, address + offset * 16 + 8, 0);
        }
        assert!(matches!(snapshot_file(&mut t), Err(error) if error == -libc::EIO));
        assert_eq!(get_elf_aux_vectors_address_at(&t, Word::MAX), 0);
    }

    #[test]
    fn fetch_auxv_stops_at_null_and_fails_on_fault() {
        let arena = Arena::new(2);
        let mut child = fork_child(&arena).unwrap();
        let t = child.tracee();
        // Auxv on page 1 without AT_NULL before the protected part.
        let a = arena.addr() + 0x1000;
        poke_word(&t, a, AT_PHENT);
        poke_word(&t, a + 8, 56);
        child.protect_page(1); // fault — fetch must give up, not loop
        assert!(fetch_elf_aux_vectors(&t, a).is_none());
    }

    fn poke_reg_sp(t: &mut Tracee, sp: Word) {
        crate::tracee::reg::poke_reg(t, crate::tracee::reg::Reg::StackPointer, sp);
    }
}
