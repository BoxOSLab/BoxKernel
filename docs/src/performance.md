# Performance

## Reducing tracer overhead

Path translation and ptrace stops dominate workloads that inspect many
files or launch many processes. The tracer now:

- reuses a component's `lstat` result during canonicalization and fake-root
  permission handling, and keeps the translated path for syscall exit;
- skips redundant symlink probes when canonicalization established that a
  path is not a symlink;
- reads ELF program-header tables in a batch and buffers shebang prefixes
  for regular files; streams retain exact reads so the interpreter can
  still read the script body;
- pools boxed path buffers to avoid moving and zeroing 4 KiB buffers;
- reads and writes adjacent uid/gid fields together;
- searches seccomp syscall numbers with a balanced tree, and checks
  arguments in the kernel for calls whose handlers only act on particular
  values. Extensions requesting every call disable that argument filter;
- reuses fetched registers at seccomp stops and obtains syscall flags
  from the filter table without another `PTRACE_GETEVENTMSG` call.

Later rounds add bounded directory caching, native ELF loading in
identity namespaces, direct absolute path pointers for eligible native
images, untraced closes, and untraced stat-family calls when no
extension rewrites their results. These defaults intentionally change
some C PRoot behavior. See [Compatibility](compatibility.md) for limits
and opt-out controls.

## Running benchmarks

Build both versions with the same release profile and toolchain, then run:

```sh
python3 benchmarks/compare.py /path/to/before/proot target/release/proot \
  --repetitions 3 --json target/performance.json
```

The script requires Python 3 and `strace`. It creates a disposable tree
with 128 directories, 512 files and 128 symlinks. Host workloads launch
100 processes, list that tree recursively, search it and import Python
modules. A repeated `stat` workload checks the same file 5,000 times.
`--rootfs /path/to/rootfs` adds process launches, an `/etc`
listing and a `/usr/share/doc` search inside an existing Linux rootfs.
Those rootfs commands require `sh`, `true`, `ls` and `find`. If Perl is
present, a rootfs workload also repeats 5,000 file-stat operations.

Each workload warms both versions, alternates their execution order and
reports median wall time. A separate `strace -c` run counts only the
tracer's syscalls, without `-f`. These counts are less sensitive to host
load than wall time. JSON output includes every timing sample, call and
wait count, binary checksums and platform information. Use `--filter`
to select workload names with a regular expression.

## First optimization round

Measured on Linux x86_64 on 2026-10-31, with Rust 1.98.1, release LTO and
three timed samples per workload. The baseline was commit `957d015`
(the ARM64/Android port), before the performance changes. Rootfs
workloads used an Ubuntu userspace with fake root, link2symlink and
symlink-size correction enabled.

| Workload | Before ms | After ms | Speedup | Tracer calls before → after |
|---|---:|---:|---:|---:|
| Host: 100 execs | 317.2 | 309.2 | 1.03x | 21,326 → 15,252 |
| Host: recursive listing | 282.3 | 226.9 | 1.24x | 37,498 → 30,833 |
| Host: file search | 73.7 | 61.1 | 1.21x | 7,632 → 6,488 |
| Host: Python imports | 428.7 | 387.8 | 1.11x | 12,086 → 9,893 |
| Rootfs: 100 execs | 498.2 | 431.2 | 1.16x | 43,638 → 33,823 |
| Rootfs: recursive listing | 99.1 | 74.6 | 1.33x | 13,944 → 8,542 |
| Rootfs: file search | 112.7 | 75.2 | 1.50x | 12,686 → 8,018 |

Wall times depend on host load, filesystem and guest libraries. These
measurements describe these workloads, rather than a universal speedup.

The BPF interpreter tests also measure work per untraced `getppid` call:
171 → 13 executed instructions for the base syscall list, and 271 → 14
with every extension's syscall list. Those figures describe the tree
without optional argument checks. In that round the default static program
grew from 537 to 624 instructions; the complete extension program shrank from
849 to 836. Both remain below the kernel's 4,096-instruction limit.

## Native execution and cache round

Measured against the previously optimized commit `9632824`, using
release LTO builds on the same x86_64 Linux host and Rust 1.98.1.
These are medians of **seven samples** per binary and workload, with
alternating order and separate syscall-count runs. Measurements use
the defaults; the harness clears inherited optimization overrides.

| Workload | Before ms | After ms | Speedup | Tracer calls before → after |
|---|---:|---:|---:|---:|
| Host: 100 execs | 354.7 | 255.0 | 1.39x | 15,251 → 6,847 |
| Host: recursive listing | 219.8 | 162.0 | 1.36x | 30,833 → 15,108 |
| Host: file search | 63.7 | 39.6 | 1.61x | 6,488 → 3,469 |
| Host: Python imports | 362.5 | 313.2 | 1.16x | 9,893 → 3,985 |
| Host: 5,000 stats | 491.6 | 295.8 | 1.66x | 57,411 → 21,040 |
| Rootfs: 100 execs | 480.6 | 452.5 | 1.06x | 33,831 → 26,447 |
| Rootfs: recursive listing | 89.6 | 83.2 | 1.08x | 8,542 → 7,242 |
| Rootfs: file search | 89.4 | 66.9 | 1.34x | 8,019 → 5,408 |
| Rootfs: 5,000 stats | 638.9 | 576.6 | 1.11x | 85,853 → 65,933 |

This round removes **15.2–63.4%** of tracer syscalls in these workloads.
Native host paths benefit most because they avoid canonicalization,
remote writes and register updates. Remapped rootfs commands retain the
custom loader and path translation; caching removes repeated directory
lookups but ptrace stops and extension processing still dominate.

The wall times in the two rounds were measured at different times on a
shared host. Compare before and after within each table; multiplying
their speedups is not a reliable cumulative measurement.

## Untraced identity stat

Measured against the release binary from the native-execution round
above, again with seven samples, release LTO, Rust 1.98.1 and the same
x86_64 host. The only behavioral change in this binary is that
`stat`, `lstat`, `newfstatat` and `statx` run untraced when every
binding is an identity mapping and no extension rewrites stat results.

| Workload | Before ms | After ms | Speedup | Tracer calls before → after |
|---|---:|---:|---:|---:|
| Host: 100 execs | 243.6 | 246.6 | 0.99x | 6,850 → 6,841 |
| Host: recursive listing | 202.0 | 125.7 | 1.61x | 15,110 → 7,656 |
| Host: file search | 48.5 | 25.9 | 1.88x | 3,423 → 1,363 |
| Host: Python imports | 345.8 | 306.5 | 1.13x | 3,938 → 1,658 |
| Host: 5,000 stats | 300.1 | 91.7 | 3.27x | 21,016 → 528 |
| Rootfs: 100 execs | 390.9 | 409.1 | 0.96x | 26,417 → 26,437 |
| Rootfs: recursive listing | 85.1 | 76.8 | 1.11x | 7,226 → 7,226 |
| Rootfs: file search | 64.0 | 61.4 | 1.04x | 5,387 → 5,389 |
| Rootfs: 5,000 stats | 624.5 | 607.1 | 1.03x | 65,933 → 65,908 |

Repeated host `stat` drops **97.5%** of its tracer syscalls. Listing
and search drop about half, because each directory entry still stops
for `open` and `getdents`. Python imports lose **57.9%** of tracer
calls and only **1.13×** of wall time; the remaining time is guest
work plus traced opens. Process launch is unchanged.

The rootfs rows stay flat on purpose. That benchmark enables fake
root, link2symlink and symlink-size correction, and each of those
extensions still traces stat so it can rewrite the result. Call-count
differences of a few dozen are run-to-run noise.

## Validation

The current Rust suite passes **485 tests**. Coverage includes BPF equivalence
across supported syscall ABIs, malformed ELF tables, streamed shebangs,
preserving a piped script's body, and reporting the guest's own
`PR_GET_NO_NEW_PRIVS` state with and without seccomp acceleration. New
coverage checks cache expiry and guest mutation visibility, native and
legacy loading, cross-ABI exec, unmodified native path pointers, proc
aliases, descriptor reuse, duplicated auxv reads, `pread`/`readv`,
partial reads with seccomp disabled, and identity `stat` matching the
kernel until fake root rewrites the owner.
Clippy passes for x86_64 Linux, ARM64 Linux, ARM64 Android and x86_64
Android. Release build, smoke checks, rustdoc and cargo-deny pass.
Cross-target linting checks source compatibility; Android execution and
native ARM64 execution require their respective platforms.

The first round's C reference suite at commit
`b27d81a68d765f3462e807f4a14e01a03f8e89ea` ran 152 targets and reported
**131 checks ok, 21 failed, 5 skipped**, with no timeouts. The failed
checks belong to 20 targets, all of which also fail against the original
binary. This establishes no additional failing targets from this patch;
it does **not** establish full compatibility with the current C reference.

The existing failing targets are:

```text
02686ecd  0dff7b0c  1fedd9a3  28066567  3c7b1e04
4171f0b5  41b3683f  571fb953  60e0614d  691786c8
6e3a9d21  7d4e2b90  7fad9686  9f16ee06  a7d92e4b
ad207330  bcf7c15f  bf7be26e  f4182ce0  f6b33793
```

They include hard-link handling, newer path syscalls and Unix socket
translation. Reference-suite parity now provides comparison evidence;
it is not a release gate. Intentional differences are documented in
[Compatibility](compatibility.md), and unexplained regressions still
require investigation.
