# Testing

## Three layers

| Layer | What | Where | Command |
|---|---|---|---|
| Unit | Pure logic (path canonicalizer, `FixedPath`, `compare_paths`) | `#[cfg(test)]` in `src/` | `cargo test` |
| Smoke | Binary boots, binds, fakes root | CI `smoke test` step | `proot -0 id -u`, `proot -b …` |
| **Reference suite** | The C implementation's full integration suite run against the Rust binary | `proot/tests/` in the C checkout | `make -C tests check` |

The Rust suite checks BoxKernel's supported behavior. The C reference
suite provides additional compatibility coverage and helps distinguish
accidental regressions from documented behavior changes.

## Running the reference suite

You need a checkout of the C reference next to this repo:

```console
$ git clone https://github.com/termux/proot.git ../proot
$ cargo build --release
$ cd ../proot/tests
$ make check PROOT=/abs/path/to/BoxKernel/target/release/proot
```

Record the reference checkout's commit with `git rev-parse HEAD`; its
tests evolve independently of this repository. Missing QEMU binaries,
32-bit libraries or other optional
tools may cause tests to be skipped. The Makefile reports `ok`,
`FAILED` and `skipped`; a test target may contain several checks.

The latest performance validation found existing compatibility failures
in the current reference suite. See [Performance](performance.md#validation)
for the reference revision, results and baseline comparison.

Reference-suite parity is not a release gate. New unexplained failures
need investigation; intentional differences need documentation and
focused BoxKernel tests. The Rust suite and CI quality checks must pass.

## Unit tests

In-file `#[cfg(test)]` modules cover the pieces with real
specifications of their own:

- `fpath.rs` — `FixedPath` NUL semantics, `push`/`pop`/`chop`,
  `substitute_prefix` branches
- `path/canon.rs` — `compare_paths` (binding-prefix matching rules)

Add tests next to the code; keep them `safe` and fast. `cargo test`
runs in CI on every push/PR.

## Debugging a failing suite test

Each test is a shell or C program asserting a guest-visible behavior.
Workflow:

```console
$ cd ../proot/tests
$ ./test-0228fbe7.sh              # see the failure directly
$ PROOT=/path/to/proot ./test-0228fbe7.sh
$ PROOT_VERBOSE=9 …               # syscall-level trace if needed
```

Then bisect the pipeline: `tracee/event` stop → `syscall/enter`
translation → `path/canon` → write-back → `syscall/exit` post-
processing. The C source is the oracle for what each stage *should*
produce.

## Performance sanity

Use the repeatable benchmark to compare release binaries on identical
workloads (Python 3 and `strace` are required):

```console
$ python3 benchmarks/compare.py /path/to/before/proot target/release/proot --json target/performance.json
$ python3 benchmarks/compare.py /path/to/before/proot target/release/proot --rootfs /path/to/rootfs
```

See [Performance](performance.md) for the workloads, methodology and
recorded results.
