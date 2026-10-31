//! Descriptor lifecycle checks for the default untraced close path.
mod common;
use common::*;

#[test]
fn pipe_close_uses_native_epipe_unless_shadowing_is_requested() {
    if !have("python3") {
        return;
    }
    let script = r#"
import errno, os
r, w = os.pipe()
os.close(r)
try:
    os.write(w, b'x')
    print('shadow')
except OSError as error:
    assert error.errno == errno.EPIPE
    print('EPIPE')
os.close(w)
"#;
    for (shadow, expected) in [("0", "EPIPE\n"), ("1", "shadow\n")] {
        let out = run_ok(
            &["python3", "-c", script],
            &[("BOXKERNEL_PIPE_SHADOW", shadow)],
        );
        assert_eq!(stdout(&out), expected);
    }
}

#[test]
fn auxv_descriptor_reuse_does_not_patch_unrelated_file_reads() {
    if !have("python3") {
        return;
    }
    // A bind forces exec through the virtualized loader so this checks
    // AT_EXECFN patching rather than the native-exec fast path.
    let fixture = Fixture::new("auxv-reuse");
    let script = r#"
import os, struct, ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
libc.read.restype = ctypes.c_ssize_t
word = struct.calcsize('P')
fmt = '=QQ' if word == 8 else '=II'
expected = struct.pack(fmt, 31, 0x12345678) + struct.pack(fmt, 0, 0)
path = '/fd-fixture/data'
with open(path, 'wb') as out:
    out.write(expected)

def read_raw(fd):
    buf = ctypes.create_string_buffer(len(expected))
    assert libc.read(fd, buf, len(expected)) == len(expected)
    return buf.raw

# The fd may be duplicated and its original number closed before reading.
auxv = os.open('/proc/self/auxv', os.O_RDONLY)
duplicate = os.dup(auxv)
os.close(auxv)
buf = ctypes.create_string_buffer(4096)
length = libc.read(duplicate, buf, len(buf))
assert length > 0
execfn = None
for offset in range(0, length - 2 * word + 1, 2 * word):
    key, value = struct.unpack_from(fmt, buf.raw, offset)
    if key == 31:
        execfn = ctypes.string_at(value)
        break
assert execfn is not None and b'python3' in execfn, execfn
# Correct bytes must also be available through syscalls the tracer does
# not intercept, even when an auxv pair straddles readv buffer boundaries.
expected_auxv = buf.raw[:length]
assert os.pread(duplicate, 4096, 0) == expected_auxv
os.lseek(duplicate, 0, os.SEEK_SET)
left, right = bytearray(17), bytearray(4096)
count = os.readv(duplicate, [left, right])
assert (left + right)[:count] == expected_auxv
# libc.read also runs under PROOT_NO_SECCOMP; neither partial vector
# reads nor unaligned file offsets may be interpreted and patched again.
for offset in (0, 1, 3, word + 1):
    for chunk_size in (1, 7, 13, 17, 31):
        os.lseek(duplicate, offset, os.SEEK_SET)
        pieces = []
        while True:
            piece = ctypes.create_string_buffer(chunk_size)
            count = libc.read(duplicate, piece, chunk_size)
            assert count >= 0
            if not count:
                break
            pieces.append(piece.raw[:count])
        assert b''.join(pieces) == expected_auxv[offset:], (offset, chunk_size)
os.close(duplicate)

for mode in ('close', 'dup2', 'close_range'):
    auxv = os.open('/proc/self/auxv', os.O_RDONLY)
    if mode == 'close':
        os.close(auxv)
        other = os.open(path, os.O_RDONLY)
        if other != auxv:
            os.dup2(other, auxv)
            os.close(other)
    elif mode == 'dup2':
        other = os.open(path, os.O_RDONLY)
        os.dup2(other, auxv)
        os.close(other)
    else:
        # close_range(2) bypasses close(2) traps even in the legacy flow.
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        result = syscall(436, auxv, auxv, 0)
        if result < 0:
            assert ctypes.get_errno() == 38  # Old kernels lack close_range.
            os.close(auxv)
        other = os.open(path, os.O_RDONLY)
        if other != auxv:
            os.dup2(other, auxv)
            os.close(other)
    assert read_raw(auxv) == expected, mode
    os.close(auxv)
print('ok')
"#;
    let bind = format!("{}:/fd-fixture", fixture.root.display());
    for env in [
        vec![("BOXKERNEL_PIPE_SHADOW", "0")],
        vec![("BOXKERNEL_PIPE_SHADOW", "0"), ("PROOT_NO_SECCOMP", "1")],
    ] {
        let out = run_ok(&["-b", &bind, "python3", "-c", script], &env);
        assert_eq!(stdout(&out), "ok\n");
    }
}
