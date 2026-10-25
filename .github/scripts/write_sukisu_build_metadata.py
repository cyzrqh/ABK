#!/usr/bin/env python3
"""Record the SukiSU identity actually passed to the kernel compiler."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def read_uapi(source):
    spec = importlib.util.spec_from_file_location(
        "read_sukisu_uapi", Path(__file__).with_name("read_sukisu_uapi.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_uapi(source)


def command_files(build_root):
    # Bazel exposes output trees through symlinks. Traverse their resolved roots
    # explicitly rather than following arbitrary source-tree symlinks in os.walk.
    roots = [build_root]
    for name in ("out", "bazel-out", "bazel-bin"):
        candidate = build_root / name
        if candidate.is_dir():
            resolved = candidate.resolve()
            if not resolved.is_relative_to(build_root.resolve()):
                roots.append(resolved)
    seen = set()
    for root in roots:
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if name not in {
                ".git", "external", "prebuilts", "node_modules"}]
            for name in files:
                if not (name.startswith(".") and name.endswith(".o.cmd")):
                    continue
                path = Path(directory) / name
                resolved = path.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    yield path


def define_values(command, name):
    # Saved Make commands retain escaped C string quotes; don't shell-execute or
    # shlex-evaluate this untrusted build output just to read compiler -D values.
    pattern = rf"(?:^|[ \t])-D{re.escape(name)}=(?:[\\\"'])*([A-Za-z0-9_.+-]+)"
    return set(re.findall(pattern, command))


def collect_metadata(source, build_root, kernel_label):
    source = Path(source)
    build_root = Path(build_root)
    values = {name: set() for name in (
        "KSU_VERSION", "EXPECTED_HASH", "EXPECTED_SIZE", "KSU_PACKAGE_NAME")}
    commands_count = 0
    for path in command_files(build_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        commands = re.findall(r"(?m)^(?:saved)?cmd_[^\n]*?:=[ \t]*(.*)$",
                              text.replace("\\\n", " "))
        for command in commands:
            path_text = str(path).replace("\\", "/")
            # Ignore other components that happen to use similarly named flags.
            if not re.search(r"(?:^|[/\\])(?:kernelsu|KernelSU)(?:[/\\])",
                             path_text + " " + command):
                continue
            versions = define_values(command, "KSU_VERSION")
            if not versions:
                continue
            commands_count += 1
            for name in values:
                values[name].update(define_values(command, name))

    for name, found in values.items():
        if len(found) != 1:
            raise ValueError(f"Expected one compiled SukiSU {name}; found {sorted(found)} "
                             f"in {commands_count} object command records")
    version = values["KSU_VERSION"].pop()
    cert_hash = values["EXPECTED_HASH"].pop().lower()
    cert_size = values["EXPECTED_SIZE"].pop()
    package = values["KSU_PACKAGE_NAME"].pop()
    if not version.isdecimal() or int(version) < 1:
        raise ValueError(f"Invalid compiled SukiSU version: {version}")
    if not re.fullmatch(r"[0-9a-f]{64}", cert_hash):
        raise ValueError("Compiled SukiSU manager certificate SHA-256 is not a 64-digit hash")
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", cert_size):
        raise ValueError(f"Invalid compiled manager certificate size: {cert_size}")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
        raise ValueError(f"Invalid compiled manager package name: {package}")
    sha = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Cannot determine the selected SukiSU source SHA")
    return {
        "schema_version": 1,
        "kernel_label": kernel_label,
        "kernel_source_sha": sha,
        "version_code": int(version),
        "uapi": read_uapi(source),
        "expected_certificate_sha256": cert_hash,
        "expected_certificate_size": int(cert_size, 0) if cert_size.lower().startswith("0x") else int(cert_size),
        "manager_package_name": package,
        "compiled_command_files_count": commands_count,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--kernel-label", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        metadata = collect_metadata(args.source, args.build_root, args.kernel_label)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot determine the compiled SukiSU manager requirements: {error}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("ABK_SUKISU_METADATA_JSON:" + json.dumps(metadata, ensure_ascii=False))


if __name__ == "__main__":
    main()
