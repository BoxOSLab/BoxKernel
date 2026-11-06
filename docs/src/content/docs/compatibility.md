---
title: Compatibility with C PRoot
description: Intentional differences from C PRoot and how to report a regression.
---

BoxKernel implements user-space rootfs translation, virtual bind mounts,
fake identity and related PRoot features. The binary remains named
`proot` and accepts familiar command lines. Exact behavioral parity with
the C implementation is not a requirement: measured performance and
documented BoxKernel behavior guide development.

## Performance-related differences

| Behavior | Default | Control |
|---|---|---|
| Directory metadata | Successful intermediate directories are cached for at most 100 ms, up to 4,096 entries. Final paths, symlinks, failures and dynamic `/proc`, `/sys`, `/dev` lookups are not cached. | Set `BOXKERNEL_NO_PATH_CACHE=1` to disable. |
| Directory changes | Intercepted guest directory, permission and namespace changes invalidate the cache at entry and exit. Changes made by unrelated host processes may remain stale until expiry. | Disable the cache when immediate visibility of external changes is required. |
| Native ELF loading | Native programs in an identity filesystem namespace use the kernel loader, ASLR and native `brk`. Rootfs remapping, QEMU, expanded scripts and nested ptrace retain the custom loader. | Set `BOXKERNEL_LEGACY_LOADER=1`, or provide `PROOT_LOADER`, to use the custom loader. |
| Temporary storage | Native commands can start with a read-only temporary directory. The custom loader, glue directories and synthesized proc files still need writable temporary storage. | Set `PROOT_TMP_DIR` to a writable location for features that need files. |
| Native absolute paths | Native images with only a single identity root binding and no policy extensions pass eligible absolute path pointers directly to the kernel. Relative paths, lexical `.`/`..`, and direct `/proc`, `/sys`, `/dev` paths retain translation when the call is still traced. | Set `BOXKERNEL_NO_NATIVE_PATHS=1` to disable. |
| Identity stat | `stat`, `lstat`, `newfstatat` and `statx` are not traced when every binding is an identity mapping and no loaded extension rewrites stat results. The kernel resolves relative paths, `..` and `/proc` itself, and a missing `statx` is not emulated. | `BOXKERNEL_NO_NATIVE_PATHS`, `BOXKERNEL_LEGACY_LOADER` or `PROOT_LOADER` restores tracing. `-0`, `-i`, `-L`, `--link2symlink` and `-k` keep these calls traced. |
| Anonymous pipe close | Closing the final pipe reader exposes normal Linux SIGPIPE/EPIPE immediately. The tracer no longer keeps an extra reader open by default. | Set `BOXKERNEL_PIPE_SHADOW=1` for the old delayed-close workaround. |
| Descriptor tracking | Auxv and netlink operations validate descriptor object identity when used, rather than trapping every `close`. Duplicated socket descriptors share emulated replies. | Requires access to `/proc/<pid>/fd`; an identity lookup failure prevents that descriptor from being emulated. |
| Legacy-loader auxv | Read-only opens of the tracee's `/proc/<pid>/auxv` use a corrected regular-file snapshot, created on first open and reused. Duplicates, partial reads, `pread` and `readv` work without read traps. | Guest changes to its saved startup argc/envp/auxv before first open may affect the snapshot or cause `EIO`. Native-loader images read their kernel auxv directly. |

The custom loader uses fixed mapping addresses; native loading restores
the kernel's normal process layout. Programs that inspect their mapping
addresses can observe this difference. These controls select particular
behaviors, rather than providing a complete C-compatibility mode.
The process name and `AT_EXECFN` follow the translated executable path
passed to the kernel, so they may use the canonical target's spelling
rather than the symlink name originally supplied.

Native path resolution preserves the kernel's pathname errors and
symlink traversal. Symlink aliases into another process's `/proc` tree
can expose its kernel view. Images using the custom loader retain the
translator even through aliases, preserving their own virtualized proc
view.

The path cache trades immediate external-change visibility for fewer
tracer syscalls. Replacing a directory from outside the traced process
tree can delay symlink and permission revalidation until expiry. As
described in the [security model](security.md), BoxKernel is not a
security isolation boundary.

## Other differences and gaps

- Android `--ashmem-memfd` emulation is not implemented.
- Some current C reference tests expose existing gaps in hard-link
  handling, newer path syscalls and Unix socket translation. See the
  [performance validation report](performance.md#validation) for the
  tested reference revision and results.
- The version banner identifies BoxKernel. Diagnostic wording and
  internal implementation are allowed to differ from C PRoot.
- Kernel errors may be returned directly where the C implementation
  previously normalized them in the tracer.

## Reporting regressions

Describe the expected BoxKernel behavior, the command and environment,
and the observed result. Include the relevant optimization controls and
a reproducer. C PRoot output is useful comparison evidence; a difference
alone does not establish a BoxKernel bug.

```console
$ proot-c -v 2 <cmd> 2>c.log
$ proot -v 2 <cmd> 2>boxkernel.log
```

Include the reference-suite test name when applicable. Intentional
differences need documentation and focused tests; unexplained failures
still require investigation.
