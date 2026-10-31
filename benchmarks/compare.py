#!/usr/bin/env python3
"""Compare two release binaries on identical, read-only guest workloads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import tempfile
import time


def run(command, env):
    started = time.perf_counter()
    result = subprocess.run(
        command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        timeout=180, check=True,
    )
    return (time.perf_counter() - started) * 1000, result.stderr.decode()


def count_calls(command, env):
    # No -f: measure the tracer itself, without tracing guest processes.
    _, summary = run(["strace", "-qq", "-c", *command], env)
    calls = stops = 0
    for line in summary.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-1] == "total":
            calls = int(fields[3])
        if len(fields) >= 5 and fields[-1] in ("wait4", "waitid"):
            stops += int(fields[3])
    if not calls:
        raise RuntimeError("strace did not produce a syscall summary: " + summary)
    return calls, stops


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--rootfs", type=Path, help="optional Linux rootfs with sh, ls, find")
    parser.add_argument("--filter", default=".", help="regular expression matching workload names")
    parser.add_argument("--json", type=Path, help="also save samples and counts as JSON")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")
    if not shutil.which("strace"):
        parser.error("strace is required to count tracer syscalls")
    binaries = [str(p.resolve(strict=True)) for p in (args.before, args.after)]
    env = dict(os.environ, LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")
    # Both binaries must use the same accelerator settings.
    for name in ("PROOT_NO_SECCOMP", "PROOT_FORCE_KOMPAT", "PROOT_VERBOSE"):
        env.pop(name, None)
    results = []
    with tempfile.TemporaryDirectory(prefix="boxkernel-bench-") as temporary:
        fixture = Path(temporary)
        for i in range(128):
            directory = fixture / f"directory-{i:03d}"
            directory.mkdir()
            for j in range(4):
                (directory / f"file-{j}").write_text("benchmark\n")
            (directory / "link").symlink_to("file-0")
        workloads = [
            ("host.exec100", [], ["/bin/sh", "-c",
                "i=0; while [ $i -lt 100 ]; do /bin/true; i=$((i+1)); done"]),
            ("host.ls", [], ["/bin/ls", "-lR", str(fixture)]),
            ("host.find", [], ["find", str(fixture), "-type", "f", "-print"]),
        ]
        if shutil.which("python3"):
            workloads.append(("host.python", [], ["python3", "-c",
                "import json, email, http.client, asyncio, unittest"]))
        if args.rootfs:
            prefix = ["-r", str(args.rootfs.resolve(strict=True)), "-0", "-w", "/",
                "-b", "/dev", "-b", "/proc", "--link2symlink", "-L", "--kill-on-exit"]
            workloads.extend([
                ("rootfs.exec100", prefix, ["/bin/sh", "-c",
                    "i=0; while [ $i -lt 100 ]; do /bin/true; i=$((i+1)); done"]),
                ("rootfs.ls", prefix, ["/bin/ls", "-lR", "/etc"]),
                ("rootfs.find", prefix, ["/usr/bin/find", "/usr/share/doc", "-type", "f"]),
            ])
        print("| Workload | Before ms | After ms | Speedup | Tracer calls before → after |")
        print("|---|---:|---:|---:|---:|")
        for name, prefix, guest in workloads:
            if not re.search(args.filter, name):
                continue
            commands = [[binary, *prefix, *guest] for binary in binaries]
            samples = [[], []]
            for command in commands:
                run(command, env)  # warm up filesystem and interpreter caches
            for repetition in range(args.repetitions):
                # Alternate order to reduce bias from load and warm caches.
                for index in ([0, 1] if repetition % 2 == 0 else [1, 0]):
                    elapsed, _ = run(commands[index], env)
                    samples[index].append(elapsed)
            counts = [count_calls(command, env) for command in commands]
            before, after = [statistics.median(sample) for sample in samples]
            print(f"| {name} | {before:.1f} | {after:.1f} | {before/after:.2f}x | "
                  f"{counts[0][0]} → {counts[1][0]} |", flush=True)
            results.append(dict(workload=name, samples_ms=samples, tracer_calls=counts,
                                median_ms=[before, after], speedup=before/after))
    if not results:
        parser.error("--filter matched no workloads")
    if args.json:
        metadata = dict(
            binaries=[dict(path=p, sha256=hashlib.sha256(Path(p).read_bytes()).hexdigest())
                      for p in binaries],
            platform=platform.platform(), repetitions=args.repetitions, results=results,
        )
        args.json.write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
