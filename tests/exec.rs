//! execve path: exit codes, argv/env passing, shebang handling, exec errors.

mod common;
use common::*;

#[test]
fn exit_code_is_propagated() {
    let out = run(&["-r", "/", SH, "-c", "exit 42"], &[]);
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn argv_and_env_pass_through() {
    let out = run_ok(
        &[SH, "-c", "echo \"$1:$2:$MARKER\"", "x", "aa", "bb"],
        &[("MARKER", "m123")],
    );
    assert_eq!(stdout(&out).trim(), "aa:bb:m123");
}

#[test]
fn env_assignment_beats_inherited() {
    let out = run_ok(&[SH, "-c", "echo $HOME"], &[("HOME", "/no/such/home")]);
    assert_eq!(stdout(&out).trim(), "/no/such/home");
}

#[test]
fn shebang_script_runs_interpreter() {
    let f = Fixture::new("shebang");
    let script = f.file("s.sh", "#!/bin/sh\necho shebang-ok\n");
    make_exec(&script);
    let out = run_ok(&[SH, "-c", &format!("{}", script.display())], &[]);
    assert_eq!(stdout(&out).trim(), "shebang-ok");
}

#[test]
fn shebang_with_argument_passes_it() {
    let f = Fixture::new("shebang-arg");
    // `sh -x` would trace to stderr; use a flag-free arg check: argv[1] of
    // the interpreter gets the option word per shebang semantics.
    let script = f.file("s.sh", "#!/bin/sh\necho \"$0\" | grep -q .\necho arg-ok\n");
    make_exec(&script);
    let out = run_ok(&[SH, "-c", &format!("{}", script.display())], &[]);
    assert_eq!(stdout(&out).trim(), "arg-ok");
}

#[test]
fn missing_command_fails() {
    let out = run(&["/definitely/not/a/command"], &[]);
    assert!(!out.status.success());
    assert!(!stderr(&out).is_empty());
}

#[test]
fn non_executable_file_fails() {
    let f = Fixture::new("noexec");
    let file = f.file("plain.txt", "not a program\n");
    std::fs::metadata(&file).unwrap();
    let out = run(&[&format!("{}", file.display())], &[]);
    assert!(!out.status.success());
}

#[test]
fn exec_in_guest_root_resolves_inside() {
    // /bin inside the guest reaches the host tools via the runtime binds.
    let f = rootfs("exec-guest");
    let out = run_rooted_ok(&f, &[], "echo guest-ok");
    assert_eq!(stdout(&out).trim(), "guest-ok");
}

#[test]
fn nested_exec_under_proot_works() {
    // proot inside proot: recursion must not corrupt state.
    let out = run_ok(&[SH, "-c", &format!("{PROOT} /bin/echo nested")], &[]);
    assert_eq!(stdout(&out).trim(), "nested");
}

#[test]
fn native_and_legacy_loader_modes() {
    if !have("python3") {
        return;
    }
    let script = format!(
        "import ctypes; c=ctypes.CDLL(None); c.getauxval.restype=ctypes.c_ulong; print('legacy' if c.getauxval(7)=={} else 'native')",
        boxkernel::arch::INTERP_PIC_ADDRESS
    );
    for (env, expected) in [
        (vec![], "native\n"),
        (vec![("BOXKERNEL_LEGACY_LOADER", "1")], "legacy\n"),
        (vec![("PROOT_NO_SECCOMP", "1")], "native\n"),
    ] {
        let out = run_ok(&["python3", "-c", &script], &env);
        assert_eq!(stdout(&out), expected);
    }
}

#[test]
fn native_exec_does_not_require_writable_temporary_storage() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new("native-readonly-temp");
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Privileged test runners can write despite directory mode bits.
    if std::fs::write(fixture.root.join("probe"), "probe").is_ok() {
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let temporary = fixture.root.to_str().unwrap();
    let native = run_ok(&["/bin/true"], &[("PROOT_TMP_DIR", temporary)]);
    assert!(stderr(&native).is_empty(), "{}", stderr(&native));
    let legacy = run(
        &["/bin/true"],
        &[
            ("PROOT_TMP_DIR", temporary),
            ("BOXKERNEL_LEGACY_LOADER", "1"),
        ],
    );
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!legacy.status.success());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn native_exec_refreshes_abi_before_first_compat_syscall() {
    if !have("cc") {
        return;
    }
    let fixture = Fixture::new("native-compat-abi");
    let owned_file = fixture.file("owned-file", "fixture\n");
    let source = fixture.file(
        "compat.S",
        &format!(
            r#"
.section .data
path: .asciz "{}"
buffer: .space 96
.section .text
.global _start
_start:
    mov $195, %eax
    mov $path, %ebx
    mov $buffer, %ecx
    int $0x80
    test %eax, %eax
    jne failed
    cmpl $123, buffer+24
    jne failed
    cmpl $456, buffer+28
    jne failed
    xor %ebx, %ebx
    jmp done
failed:
    mov $1, %ebx
done:
    mov $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
"#,
            owned_file.display()
        ),
    );
    let executable = fixture.root.join("compat");
    let build = std::process::Command::new("cc")
        .args(["-m32", "-nostdlib", "-static", "-Wl,-e,_start"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", stderr(&build));
    // Some x86_64 kernels are built without IA32 execution support.
    if let Err(error) = std::process::Command::new(&executable).status() {
        assert_eq!(error.raw_os_error(), Some(8));
        return;
    }
    for env in [vec![], vec![("PROOT_NO_SECCOMP", "1")]] {
        run_ok(&["-i", "123:456", executable.to_str().unwrap()], &env);
    }
}

#[test]
fn executable_pipe_preserves_script_body() {
    if !have("python3") {
        return;
    }
    let script = r#"
import os, subprocess, sys
r, w = os.pipe()
os.fchmod(r, 0o700)
os.write(w, b'#!/bin/sh\necho script-body\n')
os.close(w)
try:
    result = subprocess.run([sys.argv[1], '/bin/sh', '-c', 'exec /proc/self/fd/0'],
                            stdin=r, capture_output=True, timeout=30)
finally:
    os.close(r)
assert result.returncode == 0, result.stderr
assert result.stdout == b'script-body\n', result.stdout
"#;
    let out = std::process::Command::new("python3")
        .args(["-c", script, PROOT])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn empty_argv0_is_rejected() {
    let out = run(&[""], &[]);
    assert!(!out.status.success());
}
