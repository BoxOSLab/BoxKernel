//! /proc emulation: readlink of proc entries, self-referential paths,
//! and mountinfo readability inside the guest.

mod common;
use common::*;

#[test]
fn proc_self_exe_points_at_running_binary() {
    // Inside `sh -c 'readlink ...'`, self is the readlink process —
    // /proc/self/exe must resolve to its guest path.
    let f = rootfs("proc-exe");
    let out = run_rooted_ok(&f, &[], "readlink /proc/self/exe");
    let s = stdout(&out);
    assert!(
        s.trim().ends_with("/readlink"),
        "expected guest exe path, got: {s}"
    );
}

#[test]
fn proc_self_fd_resolves_real_fds() {
    let out = run_ok(
        &[SH, "-c", "exec 9</dev/null; readlink /proc/self/fd/9"],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "/dev/null");
}

#[test]
fn proc_self_cwd_matches_guest_cwd() {
    let f = rootfs("proc-cwd");
    f.dir("sub");
    let out = run_rooted_ok(&f, &["-w", "/sub"], "readlink /proc/self/cwd");
    assert_eq!(stdout(&out).trim(), "/sub");
}

#[test]
fn proc_pid_of_self_visible() {
    let out = run_ok(
        &[SH, "-c", "readlink /proc/$$/exe | grep -q . && echo pid-ok"],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "pid-ok");
}

#[test]
fn proc_mounts_readable() {
    let out = run_ok(
        &[SH, "-c", "test -r /proc/mounts && echo mounts-readable"],
        &[],
    );
    assert!(stdout(&out).contains("mounts-readable"));
}

#[test]
fn native_paths_keep_proc_exe_correct_in_both_loader_modes() {
    if !have("python3") {
        return;
    }
    let f = Fixture::new("proc-native-paths");
    f.symlink("/proc", "proc-alias");
    let alias = f
        .root
        .join("proc-alias/self/exe")
        .to_string_lossy()
        .into_owned();
    let script = r#"
import os, sys
with open('/proc/self/exe', 'rb') as direct, open(sys.argv[1], 'rb') as alias:
    left, right = os.fstat(direct.fileno()), os.fstat(alias.fileno())
    assert (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
assert os.path.realpath(os.readlink('/proc/self/exe')) == os.path.realpath(sys.executable)
print('proc-ok')
"#;
    for env in [
        vec![],
        vec![("BOXKERNEL_LEGACY_LOADER", "1")],
        vec![("BOXKERNEL_NO_NATIVE_PATHS", "1")],
    ] {
        let out = run_ok(&["python3", "-c", script, &alias], &env);
        assert_eq!(stdout(&out), "proc-ok\n");
    }
}
