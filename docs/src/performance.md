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

## Running benchmarks

Build both versions with the same release profile and toolchain, then run:

```sh
python3 benchmarks/compare.py /path/to/before/proot target/release/proot \
  --repetitions 3 --json target/performance.json
```

The script requires Python 3 and `strace`. It creates a disposable tree
with 128 directories, 512 files and 128 symlinks. Host workloads launch
100 processes, list that tree recursively, search it and import Python
modules. `--rootfs /path/to/rootfs` adds process launches, an `/etc`
listing and a `/usr/share/doc` search inside an existing Linux rootfs.
Those rootfs commands require `sh`, `true`, `ls` and `find`.

Each workload warms both versions, alternates their execution order and
reports median wall time. A separate `strace -c` run counts only the
tracer's syscalls, without `-f`. These counts are less sensitive to host
load than wall time. JSON output includes every timing sample, call and
wait count, binary checksums and platform information. Use `--filter`
to select workload names with a regular expression.

## Measurements

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
without optional argument checks. The default static program grows from
537 to 624 instructions; the complete extension program shrinks from
849 to 836. Both remain below the kernel's 4,096-instruction limit.

## Validation

The Rust suite passes **458 tests**. Coverage includes BPF equivalence
across supported syscall ABIs, malformed ELF tables, streamed shebangs,
preserving a piped script's body, and reporting the guest's own
`PR_GET_NO_NEW_PRIVS` state with and without seccomp acceleration.
Clippy passes for x86_64 Linux, ARM64 Linux, ARM64 Android and x86_64
Android. Release build, smoke checks, rustdoc and cargo-deny pass.
Cross-target linting checks source compatibility; Android execution and
native ARM64 execution require their respective platforms.

The C reference suite at commit
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
translation. They remain compatibility work required to make the full
upstream suite green.
