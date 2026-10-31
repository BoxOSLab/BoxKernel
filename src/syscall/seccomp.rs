//! Tracer-side seccomp BPF filter — port of syscall/seccomp.c.
//!
//! The filter tells the kernel to stop (SECCOMP_RET_TRACE) only on syscalls
//! PRoot actually translates, letting everything else run untraced.

use crate::Word;
use crate::sysnum::{Abi, Sysnum, detranslate_sysnum};

/// Flags attached to filtered syscalls (readable via PTRACE_GETEVENTMSG).
pub const FILTER_SYSEXIT: Word = 0x1;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// `BPF_MAXINSNS` — the kernel refuses longer filters.
const BPF_MAXINSNS: usize = 4096;

const SECCOMP_RET_KILL: u32 = 0x0000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: u64 = 2;

/// `struct sock_filter`.
#[derive(Copy, Clone, Default)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// A filtered syscall + flag (C `FilteredSysnum`).
#[derive(Copy, Clone)]
struct FilteredSysnum {
    value: Sysnum,
    flags: Word,
}

/// `proot_sysnums[]` — every syscall PRoot translates (must match
/// enter.c/exit.c coverage).
static PROOT_SYSNUMS: &[FilteredSysnum] = &[
    FilteredSysnum {
        value: Sysnum::accept,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::accept4,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::access,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::acct,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::bind,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::brk,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::chdir,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::chmod,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chown,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chown32,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chroot,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::clone,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::clone3,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::close,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::connect,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::creat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::recvfrom,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::recvmsg,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::sendmsg,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::sendto,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::socket,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::execve,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::execveat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::faccessat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::faccessat2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::fchdir,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::fchmodat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::fchownat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::fstatat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::futimesat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::getcwd,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getpeername,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getsockname,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::inotify_add_watch,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::ioctl,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::lchown,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lchown32,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lgetxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::link,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::linkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::listxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::llistxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lremovexattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lsetxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lstat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::memfd_create,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mkdir,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mkdirat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mknod,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mknodat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mount,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::name_to_handle_at,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::newfstatat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::oldlstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::oldstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::open,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::openat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::openat2,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::pivot_root,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::prctl,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::prlimit64,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::ptrace,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::readlink,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::readlinkat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::removexattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::rename,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::renameat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::renameat2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::rmdir,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::setrlimit,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::setxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::socketcall,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::stat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::stat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::statfs,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::statfs64,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::statx,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::swapoff,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::swapon,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::symlink,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::symlinkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::truncate,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::truncate64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::umount,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::umount2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::uname,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::unshare,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::setns,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::unlink,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::unlinkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::uselib,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::utime,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::utimensat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::utimes,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::wait4,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::waitpid,
        flags: FILTER_SYSEXIT,
    },
];

/// `merge_filtered_sysnums()`.
fn merge_filtered_sysnums(list: &mut Vec<FilteredSysnum>, new: &[FilteredSysnum]) {
    for n in new {
        match list.iter_mut().find(|e| e.value == n.value) {
            Some(e) => e.flags |= n.flags,
            None => list.push(*n),
        }
    }
}

/// Symbolic jump target; `Asm::finish` turns it into an offset.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Label(usize);

/// One instruction before layout. Jumps name labels, not offsets.
enum Item {
    /// LD or RET; never jumps.
    Stmt { code: u16, k: u32 },
    /// JEQ/JGT/JGE: continue at `t` if the test holds, else at `f`. `far[i]`
    /// marks side `i` (0 = t, 1 = f) as out of 8-bit reach; that side is then
    /// reached through a `JA` placed right after the jump.
    Cond {
        code: u16,
        k: u32,
        t: Label,
        f: Label,
        far: [bool; 2],
    },
    /// Marks the position a label refers to; takes no space.
    Bind(Label),
}

/// Assembler for classic BPF with symbolic labels.
#[derive(Default)]
struct Asm {
    items: Vec<Item>,
    labels: usize,
}

impl Asm {
    fn label(&mut self) -> Label {
        self.labels += 1;
        Label(self.labels - 1)
    }

    fn bind(&mut self, label: Label) {
        self.items.push(Item::Bind(label));
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.items.push(Item::Stmt { code, k });
    }

    fn cond(&mut self, code: u16, k: u32, t: Label, f: Label) {
        self.items.push(Item::Cond {
            code,
            k,
            t,
            f,
            far: [false; 2],
        });
    }

    /// Lay out the program and resolve every label.
    ///
    /// Conditional jumps carry 8-bit offsets, so a target more than 255
    /// instructions ahead is reached through a `JA` (32-bit offset) placed
    /// right after the jump. That trampoline pushes everything after it
    /// further away, so layout is repeated until no new trampoline is needed.
    /// Flags only ever turn on, which makes this terminate.
    fn finish(mut self) -> Vec<SockFilter> {
        loop {
            let mut label_at = vec![usize::MAX; self.labels];
            let mut item_at = Vec::with_capacity(self.items.len());
            let mut pc = 0usize;
            for item in &self.items {
                item_at.push(pc);
                match item {
                    Item::Bind(label) => label_at[label.0] = pc,
                    Item::Stmt { .. } => pc += 1,
                    Item::Cond { far, .. } => pc += 1 + far.iter().filter(|&&x| x).count(),
                }
            }

            let mut grew = false;
            for (item, &at) in self.items.iter_mut().zip(&item_at) {
                if let Item::Cond { t, f, far, .. } = item {
                    let next = at + 1;
                    for (side, label) in [*t, *f].into_iter().enumerate() {
                        let target = label_at[label.0];
                        assert!(
                            target != usize::MAX && target >= next,
                            "label unbound or behind its jump"
                        );
                        if !far[side] && target - next > u8::MAX as usize {
                            far[side] = true;
                            grew = true;
                        }
                    }
                }
            }
            if !grew {
                return self.emit(&label_at, &item_at);
            }
        }
    }

    /// Write the laid-out program. `label_at` and `item_at` come from the last
    /// layout pass, which already accounts for every trampoline.
    fn emit(&self, label_at: &[usize], item_at: &[usize]) -> Vec<SockFilter> {
        let mut prog = Vec::new();
        for (item, &at) in self.items.iter().zip(item_at) {
            match *item {
                Item::Bind(_) => {}
                Item::Stmt { code, k } => prog.push(stmt(code, k)),
                Item::Cond { code, k, t, f, far } => {
                    let next = at + 1;
                    let (t, f) = (label_at[t.0], label_at[f.0]);
                    match far {
                        [false, false] => prog.push(jump(code, k, short(t, next), short(f, next))),
                        [true, false] => {
                            prog.push(jump(code, k, 0, short(f, next)));
                            prog.push(stmt(BPF_JMP + BPF_JA, long(t, next + 1)));
                        }
                        [false, true] => {
                            prog.push(jump(code, k, short(t, next), 0));
                            prog.push(stmt(BPF_JMP + BPF_JA, long(f, next + 1)));
                        }
                        [true, true] => {
                            prog.push(jump(code, k, 0, 1));
                            prog.push(stmt(BPF_JMP + BPF_JA, long(t, next + 1)));
                            prog.push(stmt(BPF_JMP + BPF_JA, long(f, next + 2)));
                        }
                    }
                }
            }
        }
        prog
    }
}

/// 8-bit jump offset from `from` to `target`; the layout guarantees it fits.
fn short(target: usize, from: usize) -> u8 {
    u8::try_from(target - from).expect("conditional jump within 255 instructions")
}

/// 32-bit `JA` offset from `from` to `target`.
fn long(target: usize, from: usize) -> u32 {
    u32::try_from(target - from).expect("filter fits a 32-bit jump")
}

/// Consecutive syscall numbers that share one return value.
#[derive(Copy, Clone)]
struct Run {
    lo: u32,
    hi: u32,
    ret: u32,
    /// Set on a single-number run traced only for some argument values.
    filter: Option<&'static ArgFilter>,
}

/// A syscall PRoot only needs to stop for when its arguments pass every
/// check; any other call runs untraced.  The checks may let through calls
/// the handlers then ignore, never drop one they act on.
pub(crate) struct ArgFilter {
    sysnum: Sysnum,
    /// (0-based argument index, check), all of which must hold.
    checks: &'static [(u32, ArgCheck)],
}

pub(crate) enum ArgCheck {
    /// The low 32 bits of the argument are one of these values.
    OneOf(&'static [u32]),
    /// The argument (a pointer) is not NULL.
    NonZero,
}

/// `FICLONE`, `_IOW(0x94, 9, int)`.
const FICLONE: u32 = 0x4004_9409;
// The libc type of resource numbers differs between glibc and Bionic.
#[allow(clippy::unnecessary_cast)]
const RLIMIT_STACK: u32 = libc::RLIMIT_STACK as u32;

/// The syscalls PRoot traces for only a few argument values, after their
/// handlers in syscall/enter.rs and syscall/exit.rs.
const ARG_FILTERS: &[ArgFilter] = &[
    // The most frequent syscall PRoot used to stop for in vain: isatty()
    // alone issues one per opened file.  Only SIOCGIFINDEX is emulated
    // (sysenter) and FICLONE fixed up (sysexit).
    ArgFilter {
        sysnum: Sysnum::ioctl,
        checks: &[(1, ArgCheck::OneOf(&[FICLONE, libc::SIOCGIFINDEX as u32]))],
    },
    // Only a new RLIMIT_STACK limit matters (sysexit); every dynamically
    // linked program reads that limit at startup.
    ArgFilter {
        sysnum: Sysnum::prlimit64,
        checks: &[
            (1, ArgCheck::OneOf(&[RLIMIT_STACK])),
            (2, ArgCheck::NonZero),
        ],
    },
    ArgFilter {
        sysnum: Sysnum::setrlimit,
        checks: &[(0, ArgCheck::OneOf(&[RLIMIT_STACK]))],
    },
    // PR_SET_DUMPABLE, PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS,
    // PR_GET_NO_NEW_PRIVS and PR_GET_AUXV.
    ArgFilter {
        sysnum: Sysnum::prctl,
        checks: &[(0, ArgCheck::OneOf(&[4, 22, 38, 39, 0x4155_5856]))],
    },
];

/// Offset of the low (`high` = false) or high 32 bits of argument `arg` in
/// `struct seccomp_data`.
fn arg_word_offset(arg: u32, high: bool) -> u32 {
    let args = 16; // offsetof(seccomp_data, args)
    args + 8 * arg
        + if high == cfg!(target_endian = "big") {
            0
        } else {
            4
        }
}

/// The `(nr, action)` pairs one arch section traces, sorted by number, with
/// neighbours that share an action merged into runs.
///
/// A number listed twice keeps the action of its first listing, as a linear
/// chain of comparisons would.
fn section_runs(
    abis: &[Abi],
    sysnums: &[FilteredSysnum],
    arg_filters: &[&'static ArgFilter],
) -> Vec<Run> {
    let mut points: Vec<(u32, u32, Option<&'static ArgFilter>)> = Vec::new();
    for abi in abis {
        for s in sysnums {
            let syscall = detranslate_sysnum(*abi, s.value);
            if syscall == crate::arch::SYSCALL_AVOIDER || syscall > u32::MAX as Word {
                continue;
            }
            let filter = arg_filters.iter().find(|f| f.sysnum == s.value).copied();
            points.push((syscall as u32, SECCOMP_RET_TRACE + s.flags as u32, filter));
        }
    }
    // The sort is stable, so the first listing of each number comes first and
    // `dedup_by_key` keeps it.
    points.sort_by_key(|p| p.0);
    points.dedup_by_key(|p| p.0);

    let mut runs: Vec<Run> = Vec::new();
    for (nr, ret, filter) in points {
        match runs.last_mut() {
            Some(run)
                if run.ret == ret
                    && run.hi + 1 == nr
                    && run.filter.is_none()
                    && filter.is_none() =>
            {
                run.hi = nr
            }
            _ => runs.push(Run {
                lo: nr,
                hi: nr,
                ret,
                filter,
            }),
        }
    }
    runs
}

/// Emit a balanced binary search over `runs`. An internal node splits on the
/// first number of its right half, so a lookup costs O(log n) tests. Numbers
/// outside every run jump to `miss`.
fn emit_search(asm: &mut Asm, runs: &[Run], miss: Label) {
    match runs {
        [] => {}
        [run] => emit_leaf(asm, *run, miss),
        _ => {
            let mid = runs.len() / 2;
            let left = asm.label();
            let right = asm.label();
            // nr >= first number of the right half: search right, else left.
            asm.cond(BPF_JMP + BPF_JGE + BPF_K, runs[mid].lo, right, left);
            asm.bind(left);
            emit_search(asm, &runs[..mid], miss);
            asm.bind(right);
            emit_search(asm, &runs[mid..], miss);
        }
    }
}

/// Test a single run: a lone number needs one comparison, a range two.
fn emit_leaf(asm: &mut Asm, run: Run, miss: Label) {
    if run.lo == run.hi {
        let hit = asm.label();
        asm.cond(BPF_JMP + BPF_JEQ + BPF_K, run.lo, hit, miss);
        asm.bind(hit);
    } else {
        let in_range = asm.label();
        asm.cond(BPF_JMP + BPF_JGE + BPF_K, run.lo, in_range, miss);
        asm.bind(in_range);
        let hit = asm.label();
        asm.cond(BPF_JMP + BPF_JGT + BPF_K, run.hi, miss, hit);
        asm.bind(hit);
    }
    if let Some(filter) = run.filter {
        // The number matched: now every argument check must pass.
        for (arg, check) in filter.checks {
            let pass = asm.label();
            match check {
                ArgCheck::OneOf(values) => {
                    asm.stmt(BPF_LD + BPF_W + BPF_ABS, arg_word_offset(*arg, false));
                    for (i, &value) in values.iter().enumerate() {
                        let next = asm.label();
                        let last = i + 1 == values.len();
                        asm.cond(
                            BPF_JMP + BPF_JEQ + BPF_K,
                            value,
                            pass,
                            if last { miss } else { next },
                        );
                        asm.bind(next);
                    }
                }
                ArgCheck::NonZero => {
                    let high = asm.label();
                    asm.stmt(BPF_LD + BPF_W + BPF_ABS, arg_word_offset(*arg, false));
                    asm.cond(BPF_JMP + BPF_JEQ + BPF_K, 0, high, pass);
                    asm.bind(high);
                    asm.stmt(BPF_LD + BPF_W + BPF_ABS, arg_word_offset(*arg, true));
                    asm.cond(BPF_JMP + BPF_JEQ + BPF_K, 0, miss, pass);
                }
            }
            asm.bind(pass);
        }
    }
    asm.stmt(BPF_RET + BPF_K, run.ret);
}

/// Build the filter for `sysnums`. Per arch in `SECCOMP_ARCHS`: check
/// `seccomp_data.arch`, then search that arch's numbers over all of its ABIs,
/// allowing the numbers that are not listed. An arch no section matches is
/// killed.
#[cfg(test)]
fn build_filter(sysnums: &[FilteredSysnum]) -> Vec<SockFilter> {
    build_filter_with(sysnums, &[])
}

/// `build_filter()`, where the syscalls of `arg_filters` are only traced for
/// the argument values they list.
fn build_filter_with(
    sysnums: &[FilteredSysnum],
    arg_filters: &[&'static ArgFilter],
) -> Vec<SockFilter> {
    let arch_offset = 4u32; // offsetof(seccomp_data, arch)
    let nr_offset = 0u32; // offsetof(seccomp_data, nr)

    let mut asm = Asm::default();
    for arch in crate::arch::SECCOMP_ARCHS {
        let next_arch = asm.label();
        let matched = asm.label();
        asm.stmt(BPF_LD + BPF_W + BPF_ABS, arch_offset);
        asm.cond(BPF_JMP + BPF_JEQ + BPF_K, arch.value, matched, next_arch);
        asm.bind(matched);
        asm.stmt(BPF_LD + BPF_W + BPF_ABS, nr_offset);

        let allow = asm.label();
        emit_search(
            &mut asm,
            &section_runs(arch.abis, sysnums, arg_filters),
            allow,
        );
        asm.bind(allow);
        asm.stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
        asm.bind(next_arch);
    }
    asm.stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL);

    let prog = asm.finish();
    debug_assert!(prog.len() <= BPF_MAXINSNS);
    prog
}

/// `set_seccomp_filters()` — build the filter (see `build_filter`) and
/// install it.
fn set_seccomp_filters(sysnums: &[FilteredSysnum], arg_filters: &[&'static ArgFilter]) -> i32 {
    let prog = build_filter_with(sysnums, arg_filters);

    let mut fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *const _ as *mut libc::sock_filter,
    };

    if crate::sys::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        return -crate::sys::errno();
    }
    if crate::sys::prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER as usize,
        &mut fprog as *mut _ as usize,
        0,
        0,
    ) < 0
    {
        return -crate::sys::errno();
    }
    0
}

/// `enable_syscall_filtering()` — merge PRoot's sysnums with the ones the
/// tracee's extensions need, then install the filter (called in the child
/// before exec).
pub fn enable_syscall_filtering(tracee: &crate::tracee::Tracee) -> i32 {
    let mut filtered = Vec::new();
    merge_filtered_sysnums(&mut filtered, PROOT_SYSNUMS);
    for ext in tracee.extensions.iter().flatten() {
        let tmp: Vec<FilteredSysnum> = ext
            .filtered_sysnums()
            .iter()
            .map(|&(value, flags)| FilteredSysnum { value, flags })
            .collect();
        merge_filtered_sysnums(&mut filtered, &tmp);
    }
    // An extension that wants a syscall may want every call of it.
    let arg_filters: Vec<&'static ArgFilter> = ARG_FILTERS
        .iter()
        .filter(|f| {
            !tracee
                .extensions
                .iter()
                .flatten()
                .any(|e| e.filtered_sysnums().iter().any(|&(s, _)| s == f.sysnum))
        })
        .collect();
    set_seccomp_filters(&filtered, &arg_filters)
}

/// `filtered_sysnum_flags()` — flags the installed filter attaches to
/// @sysnum's PTRACE_EVENT_SECCOMP stops.
pub fn filtered_sysnum_flags(tracee: &crate::tracee::Tracee, sysnum: Sysnum) -> Word {
    let mut flags: Word = 0;
    for s in PROOT_SYSNUMS {
        if s.value == sysnum {
            flags |= s.flags;
        }
    }
    for ext in tracee.extensions.iter().flatten() {
        for &(value, f) in ext.filtered_sysnums() {
            if value == sysnum {
                flags |= f;
            }
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stmt_and_jump_layout() {
        let s = stmt(BPF_LD, 42);
        assert_eq!((s.code, s.jt, s.jf, s.k), (BPF_LD, 0, 0, 42));
        let j = jump(BPF_JMP, 7, 1, 2);
        assert_eq!((j.code, j.jt, j.jf, j.k), (BPF_JMP, 1, 2, 7));
        assert_eq!(size_of::<SockFilter>(), 8);
    }

    #[test]
    fn merge_filtered_sysnums_or_flags() {
        let mut list: Vec<FilteredSysnum> = Vec::new();
        let a = FilteredSysnum {
            value: Sysnum::openat,
            flags: 1,
        };
        let b = FilteredSysnum {
            value: Sysnum::read,
            flags: 2,
        };
        merge_filtered_sysnums(&mut list, &[a, b]);
        assert_eq!(list.len(), 2);
        // Merging the same sysnum again ORs the flags in place.
        let a2 = FilteredSysnum {
            value: Sysnum::openat,
            flags: 4,
        };
        merge_filtered_sysnums(&mut list, &[a2]);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].flags, 1 | 4);
        assert_eq!(list[1].flags, 2);
    }

    use crate::arch::{
        AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, SYSCALL_AVOIDER,
    };
    use crate::extension::AnyExtension;

    // ----- Reference: the linear builder this module replaced -----------

    /// The old `start_arch_section()`. Its skip over the section is a `JA`.
    /// (The old code spelled that opcode `BPF_JMP + 0x20`, which is `JGT`, a
    /// no-op: every arch then fell into the first section. The reference
    /// below encodes the intended `JA`.)
    fn ref_start_arch_section(prog: &mut Vec<SockFilter>, arch: u32, nb_traced: usize) {
        let arch_offset = 4u32; // offsetof(seccomp_data, arch)
        let nr_offset = 0u32; // offsetof(seccomp_data, nr)
        let section_length = 1 + nb_traced * 2; // END + trace stmts

        prog.push(stmt(BPF_LD + BPF_W + BPF_ABS, arch_offset));
        prog.push(jump(BPF_JMP + BPF_JEQ + BPF_K, arch, 1, 0));
        prog.push(stmt(BPF_JMP + BPF_JA, (section_length + 1) as u32));
        prog.push(stmt(BPF_LD + BPF_W + BPF_ABS, nr_offset));
    }

    /// The old linear builder: one `JEQ`/`RET` pair per traced number.
    fn reference_filter(sysnums: &[FilteredSysnum]) -> Vec<SockFilter> {
        let mut prog: Vec<SockFilter> = Vec::new();
        for arch in crate::arch::SECCOMP_ARCHS {
            // (nr, action) in listing order, one entry per (abi, sysnum).
            let mut traced: Vec<(u32, u32)> = Vec::new();
            for abi in arch.abis {
                for s in sysnums {
                    let syscall = detranslate_sysnum(*abi, s.value);
                    if syscall != SYSCALL_AVOIDER {
                        let nr = u32::try_from(syscall).expect("syscall number fits u32");
                        traced.push((nr, SECCOMP_RET_TRACE + s.flags as u32));
                    }
                }
            }

            ref_start_arch_section(&mut prog, arch.value, traced.len());
            for (nr, ret) in traced {
                prog.push(jump(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1));
                prog.push(stmt(BPF_RET + BPF_K, ret));
            }
            prog.push(stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
        }
        prog.push(stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL));
        prog
    }

    // ----- Classic BPF interpreter (only the opcodes used above) --------

    /// `struct seccomp_data` for a syscall with this arch and nr; the
    /// instruction pointer and arguments are zero.
    fn seccomp_data(arch: u32, nr: u32) -> [u8; 64] {
        seccomp_data_args(arch, nr, [0; 6])
    }

    fn seccomp_data_args(arch: u32, nr: u32, args: [u64; 6]) -> [u8; 64] {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        data
    }

    /// The kernel's static checks, for the subset used here: known opcodes,
    /// every jump landing inside the program, and a final RET.
    fn validate(prog: &[SockFilter]) {
        assert!(
            !prog.is_empty() && prog.len() <= BPF_MAXINSNS,
            "length {}",
            prog.len()
        );
        assert_eq!(prog[prog.len() - 1].code, BPF_RET + BPF_K, "last insn");
        for (pc, ins) in prog.iter().enumerate() {
            let next = pc + 1;
            match ins.code {
                c if c == BPF_LD + BPF_W + BPF_ABS => {}
                c if c == BPF_JMP + BPF_JA => {
                    let target = next + (ins.k as usize);
                    assert!(target < prog.len(), "JA out of range at {pc}");
                }
                c if c == BPF_JMP + BPF_JEQ + BPF_K
                    || c == BPF_JMP + BPF_JGT + BPF_K
                    || c == BPF_JMP + BPF_JGE + BPF_K =>
                {
                    let t = next + usize::from(ins.jt);
                    let f = next + usize::from(ins.jf);
                    assert!(
                        t < prog.len() && f < prog.len(),
                        "conditional jump out of range at {pc}"
                    );
                }
                c if c == BPF_RET + BPF_K => {}
                c => panic!("unsupported opcode {c:#x} at {pc}"),
            }
        }
    }

    /// Runs `prog` on (arch, nr). Returns the RET value and how many
    /// instructions were executed.
    fn run_counted(prog: &[SockFilter], arch: u32, nr: u32) -> (u32, usize) {
        run_data(prog, &seccomp_data(arch, nr))
    }

    fn run_data(prog: &[SockFilter], data: &[u8; 64]) -> (u32, usize) {
        let mut acc = 0u32;
        let mut pc = 0usize;
        let mut steps = 0usize;
        loop {
            let ins = prog[pc];
            pc += 1;
            steps += 1;
            let skip = |cond: bool| usize::from(if cond { ins.jt } else { ins.jf });
            match ins.code {
                c if c == BPF_LD + BPF_W + BPF_ABS => {
                    let off = ins.k as usize;
                    acc = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap());
                }
                c if c == BPF_JMP + BPF_JA => pc += ins.k as usize,
                c if c == BPF_JMP + BPF_JEQ + BPF_K => pc += skip(acc == ins.k),
                c if c == BPF_JMP + BPF_JGT + BPF_K => pc += skip(acc > ins.k),
                c if c == BPF_JMP + BPF_JGE + BPF_K => pc += skip(acc >= ins.k),
                c if c == BPF_RET + BPF_K => return (ins.k, steps),
                c => panic!("unsupported opcode {c:#x}"),
            }
        }
    }

    /// Runs `prog` on (arch, nr) and returns the RET value.
    fn run(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
        run_counted(prog, arch, nr).0
    }

    // ----- Equivalence ---------------------------------------------------

    /// `PROOT_SYSNUMS` merged with every built-in extension's
    /// `filtered_sysnums()`, as `enable_syscall_filtering()` does it.
    fn all_extension_sysnums() -> Vec<FilteredSysnum> {
        let exts = [
            AnyExtension::FakeId0(Default::default()),
            AnyExtension::Link2Symlink(Default::default()),
            AnyExtension::HiddenFiles(Default::default()),
            AnyExtension::PortSwitch(Default::default()),
            AnyExtension::FixSymlinkSize(Default::default()),
            AnyExtension::Kompat(Default::default()),
            AnyExtension::Mountinfo(Default::default()),
            AnyExtension::Sysvipc(Default::default()),
        ];
        let mut list = Vec::new();
        merge_filtered_sysnums(&mut list, PROOT_SYSNUMS);
        for ext in &exts {
            let own: Vec<FilteredSysnum> = ext
                .filtered_sysnums()
                .iter()
                .map(|&(value, flags)| FilteredSysnum { value, flags })
                .collect();
            merge_filtered_sysnums(&mut list, &own);
        }
        list
    }

    /// Every arch the filter knows, plus some it must kill.
    fn probe_arches() -> Vec<u32> {
        let mut arches: Vec<u32> = crate::arch::SECCOMP_ARCHS.iter().map(|a| a.value).collect();
        let candidates = [
            0,
            1,
            0x1234_5678,
            u32::MAX,
            AUDIT_ARCH_I386,
            AUDIT_ARCH_X86_64,
            AUDIT_ARCH_ARM,
            AUDIT_ARCH_AARCH64,
            AUDIT_ARCH_X86_64 ^ 0x1_0000,
        ];
        for cand in candidates {
            if !arches.contains(&cand) {
                arches.push(cand);
            }
        }
        arches
    }

    /// nr 0..=2048, the x32 range from 0x4000_0000, and the top of u32.
    fn probe_nrs() -> impl Iterator<Item = u32> {
        (0u32..=2048)
            .chain(0x4000_0000..=0x4000_0000 + 2048)
            .chain(u32::MAX - 2048..=u32::MAX)
    }

    /// The new filter returns the reference's action for every probe.
    fn assert_equivalent(sysnums: &[FilteredSysnum]) {
        let new = build_filter(sysnums);
        let old = reference_filter(sysnums);
        validate(&new);
        validate(&old);
        assert!(new.len() <= BPF_MAXINSNS);
        for arch in probe_arches() {
            for nr in probe_nrs() {
                assert_eq!(
                    run(&new, arch, nr),
                    run(&old, arch, nr),
                    "arch {arch:#x} nr {nr:#x}"
                );
            }
        }
    }

    #[test]
    fn equivalent_to_linear_default_list() {
        assert_equivalent(PROOT_SYSNUMS);
    }

    #[test]
    fn equivalent_to_linear_all_extensions() {
        assert_equivalent(&all_extension_sysnums());
    }

    #[test]
    fn equivalent_for_empty_list() {
        assert_equivalent(&[]);
    }

    #[test]
    fn equivalent_for_single_syscall() {
        assert_equivalent(&[FilteredSysnum {
            value: Sysnum::read,
            flags: FILTER_SYSEXIT,
        }]);
    }

    #[test]
    fn equivalent_for_duplicates() {
        let traced = FilteredSysnum {
            value: Sysnum::read,
            flags: 0,
        };
        let sysexit = FilteredSysnum {
            value: Sysnum::read,
            flags: FILTER_SYSEXIT,
        };
        let write = FilteredSysnum {
            value: Sysnum::write,
            flags: 0,
        };
        assert_equivalent(&[traced, traced]);
        assert_equivalent(&[traced, sysexit, write, sysexit]);
        assert_equivalent(&[sysexit, traced, write]);
    }

    #[test]
    fn duplicate_keeps_first_listing() {
        let arch = crate::arch::SECCOMP_ARCHS[0];
        let read_nr = detranslate_sysnum(Abi::Default, Sysnum::read) as u32;
        let prog = build_filter(&[
            FilteredSysnum {
                value: Sysnum::read,
                flags: FILTER_SYSEXIT,
            },
            FilteredSysnum {
                value: Sysnum::read,
                flags: 0,
            },
        ]);
        assert_eq!(
            run(&prog, arch.value, read_nr),
            SECCOMP_RET_TRACE + FILTER_SYSEXIT as u32
        );
    }

    // ----- Direct checks -------------------------------------------------

    #[test]
    fn arg_filtered_syscalls_traced_only_when_handled() {
        let filters: Vec<&'static ArgFilter> = ARG_FILTERS.iter().collect();
        let prog = build_filter_with(PROOT_SYSNUMS, &filters);
        validate(&prog);
        let ioctl_flags = PROOT_SYSNUMS
            .iter()
            .find(|s| s.value == Sysnum::ioctl)
            .unwrap()
            .flags;
        for arch in crate::arch::SECCOMP_ARCHS {
            for abi in arch.abis {
                let nr = detranslate_sysnum(*abi, Sysnum::ioctl);
                if nr == SYSCALL_AVOIDER {
                    continue;
                }
                let ret = |cmd: u64| {
                    run_data(
                        &prog,
                        &seccomp_data_args(arch.value, nr as u32, [3, cmd, 0, 0, 0, 0]),
                    )
                    .0
                };
                let traced = SECCOMP_RET_TRACE + ioctl_flags as u32;
                assert_eq!(ret(FICLONE as u64), traced);
                assert_eq!(ret(libc::SIOCGIFINDEX as Word), traced);
                // Upper bits aren't looked at: stopping is the safe side.
                assert_eq!(ret(0xffff_ffff_0000_0000 | FICLONE as u64), traced);
                assert_eq!(ret(libc::TCGETS as Word), SECCOMP_RET_ALLOW);
                assert_eq!(ret(0), SECCOMP_RET_ALLOW);
                assert_eq!(ret(FICLONE as u64 + 1), SECCOMP_RET_ALLOW);
            }
            let flags_of = |sysnum: Sysnum| {
                SECCOMP_RET_TRACE
                    + PROOT_SYSNUMS
                        .iter()
                        .find(|s| s.value == sysnum)
                        .unwrap()
                        .flags as u32
            };
            for abi in arch.abis {
                let nr = |sysnum: Sysnum| detranslate_sysnum(*abi, sysnum);
                let ret = |sysnum: Sysnum, args: [u64; 6]| {
                    run_data(
                        &prog,
                        &seccomp_data_args(arch.value, nr(sysnum) as u32, args),
                    )
                    .0
                };
                if nr(Sysnum::prlimit64) != SYSCALL_AVOIDER {
                    let traced = flags_of(Sysnum::prlimit64);
                    let stack = libc::RLIMIT_STACK as u64;
                    assert_eq!(ret(Sysnum::prlimit64, [0, stack, 0x7ff0, 0, 0, 0]), traced);
                    assert_eq!(ret(Sysnum::prlimit64, [0, stack, 1 << 40, 0, 0, 0]), traced);
                    // A mere read of the limit, or another resource: untraced.
                    let allow = SECCOMP_RET_ALLOW;
                    assert_eq!(ret(Sysnum::prlimit64, [0, stack, 0, 0x7ff0, 0, 0]), allow);
                    assert_eq!(ret(Sysnum::prlimit64, [0, 7, 0x7ff0, 0, 0, 0]), allow);
                }
                if nr(Sysnum::setrlimit) != SYSCALL_AVOIDER {
                    let stack = libc::RLIMIT_STACK as u64;
                    let traced = flags_of(Sysnum::setrlimit);
                    assert_eq!(ret(Sysnum::setrlimit, [stack, 0x7ff0, 0, 0, 0, 0]), traced);
                    assert_eq!(
                        ret(Sysnum::setrlimit, [7, 0x7ff0, 0, 0, 0, 0]),
                        SECCOMP_RET_ALLOW
                    );
                }
                if nr(Sysnum::prctl) != SYSCALL_AVOIDER {
                    let traced = flags_of(Sysnum::prctl);
                    for option in [4u64, 22, 38, 39, 0x4155_5856] {
                        assert_eq!(ret(Sysnum::prctl, [option, 0, 0, 0, 0, 0]), traced);
                    }
                    // PR_SET_NAME
                    assert_eq!(ret(Sysnum::prctl, [15, 0, 0, 0, 0, 0]), SECCOMP_RET_ALLOW);
                }
            }
            // Every other syscall is unaffected by the argument filters.
            for nr in (0..=1024u32).chain(0x4000_0000..=0x4000_0400) {
                let filtered = arch.abis.iter().any(|abi| {
                    ARG_FILTERS
                        .iter()
                        .any(|f| detranslate_sysnum(*abi, f.sysnum) == nr as Word)
                });
                if filtered {
                    continue;
                }
                let data = seccomp_data_args(arch.value, nr, [3, 0x5401, 0, 0, 0, 0]);
                assert_eq!(
                    run_data(&prog, &data).0,
                    run(&build_filter(PROOT_SYSNUMS), arch.value, nr),
                    "{:#x} nr {nr}",
                    arch.value
                );
            }
        }
    }

    #[test]
    fn dispatches_each_abi_under_its_arch() {
        let prog = build_filter(PROOT_SYSNUMS);
        for arch in crate::arch::SECCOMP_ARCHS {
            for abi in arch.abis {
                for s in PROOT_SYSNUMS {
                    let nr = detranslate_sysnum(*abi, s.value);
                    if nr == SYSCALL_AVOIDER {
                        continue;
                    }
                    assert_eq!(
                        run(&prog, arch.value, nr as u32),
                        SECCOMP_RET_TRACE + s.flags as u32,
                        "{:?} {:?}",
                        abi,
                        s.value
                    );
                }
            }
        }
        let unknown = probe_arches()
            .into_iter()
            .find(|a| !crate::arch::SECCOMP_ARCHS.iter().any(|k| k.value == *a))
            .unwrap();
        assert_eq!(run(&prog, unknown, 0), SECCOMP_RET_KILL);
    }

    #[test]
    fn consecutive_numbers_with_one_action_merge() {
        let read = FilteredSysnum {
            value: Sysnum::read,
            flags: 0,
        };
        let write = FilteredSysnum {
            value: Sysnum::write,
            flags: 0,
        };
        let runs = section_runs(&[Abi::Default], &[read, write], &[]);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].hi, runs[0].lo + 1);

        let write_sysexit = FilteredSysnum {
            value: Sysnum::write,
            flags: FILTER_SYSEXIT,
        };
        let runs = section_runs(&[Abi::Default], &[read, write_sysexit], &[]);
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn instruction_counts() {
        // getppid is not in any list, so an untraced call takes the ALLOW path
        // and runs the whole dispatch.
        let getppid = detranslate_sysnum(Abi::Default, Sysnum::getppid) as u32;
        let arch = crate::arch::SECCOMP_ARCHS[0].value;
        let all = all_extension_sysnums();
        for (name, list) in [("default", PROOT_SYSNUMS.to_vec()), ("all extensions", all)] {
            let old = reference_filter(&list);
            let new = build_filter(&list);
            let ja = new.iter().filter(|i| i.code == BPF_JMP + BPF_JA).count();
            let (old_ret, old_steps) = run_counted(&old, arch, getppid);
            let (new_ret, new_steps) = run_counted(&new, arch, getppid);
            println!(
                "{name}: static linear {} insns, tree {} insns ({ja} JA); \
                 untraced getppid executes linear {old_steps}, tree {new_steps}",
                old.len(),
                new.len()
            );
            assert_eq!(old_ret, SECCOMP_RET_ALLOW);
            assert_eq!(new_ret, SECCOMP_RET_ALLOW);
            assert!(new.len() <= BPF_MAXINSNS);
            assert!(new_steps < old_steps);
        }
    }
}
