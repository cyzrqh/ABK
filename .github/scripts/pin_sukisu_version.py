#!/usr/bin/env python3
"""Derive SukiSU display metadata from the checked-out source, like its manager."""

import argparse
import os
from pathlib import Path
import re
import subprocess


def git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, encoding="utf-8"
    ).strip()


def source_metadata(root):
    if git(root, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("SukiSU history is shallow; cannot match the official manager version")
    # These are the same HEAD-based commands and formula as manager/build.gradle.kts.
    count = int(git(root, "rev-list", "--count", "HEAD"))
    tag = git(root, "describe", "--tags", "--always", "--abbrev=0")
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", tag):
        raise ValueError(f"Unsupported SukiSU version tag: {tag!r}")
    return {
        "sha": git(root, "rev-parse", "HEAD"),
        "version": 40000 + count - 2815,
        "tag": tag.removeprefix("v"),
        "branch": git(root, "rev-parse", "--abbrev-ref", "HEAD"),
    }


def pin_version(root, custom_tag=""):
    root = Path(root)
    metadata = source_metadata(root)
    kbuild = root / "kernel/Kbuild"
    original = kbuild.read_text(encoding="utf-8")
    # Both the old and current SukiSU layouts have these final assignments.
    # Require the complete known layout before changing any file.
    assignments = ("KSU_VERSION", "VERSION_TAG", "KSU_VERSION_FULL",
                   "KSU_GITHUB_VER", "GITHUB_COMMITS")
    for variable in assignments:
        if len(re.findall(rf"^{variable}[ \t]*:=[^\n]*$", original, re.M)) != 1:
            raise ValueError(f"Unsupported SukiSU Kbuild: expected one {variable} assignment")
    if custom_tag and not re.fullmatch(r"[\w.@+\-\[\]]+", custom_tag):
        raise ValueError("SukiSU custom display tag contains unsupported Make/C string characters")
    branch = metadata["branch"]
    if not re.fullmatch(r"[A-Za-z0-9._/+-]+", branch):
        raise ValueError(f"Unsupported SukiSU source branch: {branch!r}")
    short_sha = metadata["sha"][:8]
    full = (f'v{metadata["tag"]}-{custom_tag}@{branch}[{short_sha}]'
            if custom_tag else f'v{metadata["tag"]}-{short_sha}@{branch}')
    replacements = {
        "KSU_VERSION": str(metadata["version"]),
        "VERSION_TAG": metadata["tag"],
        "KSU_VERSION_FULL": full,
        # These upstream := expressions query current main/releases immediately.
        # They must not run even though their results are no longer used.
        "KSU_GITHUB_VER": "",
        "GITHUB_COMMITS": "",
    }
    result = original
    for variable, value in replacements.items():
        result = re.sub(rf"^{variable}[ \t]*:=[^\n]*$",
                        lambda match: f"{variable} := {value}", result, flags=re.M)
    if result != original:
        kbuild.write_text(result, encoding="utf-8", newline="\n")
    metadata["full"] = full
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    metadata = pin_version(args.source, os.environ.get("CUSTOM_TAG", ""))
    print(f'SukiSU pinned display version: {metadata["version"]} [{metadata["full"]}]')
    print(f'SukiSU version source: {metadata["sha"]}')
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write(f'KSU_VERSION={metadata["version"]}\n')


if __name__ == "__main__":
    main()
