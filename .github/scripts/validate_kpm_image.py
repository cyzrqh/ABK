#!/usr/bin/env python3
"""Reject broken ARM64 KernelPatch loaders before packaging an Image.

This checks the pinned KernelPatch 0.13 ARM64 preset layout. It does not
prove device/KMI compatibility or replace a real boot test.
Layout: SukiSU-Ultra/SukiSU_KernelPatch_patch/tools/preset.h at 0.13.0.
"""

import argparse
import json
from pathlib import Path
import re
import struct


PAGE = 0x1000
PRESET_SIZE = 0x578


def require(condition, message):
    if not condition:
        raise ValueError(message)


def arm64_header(image):
    require(len(image) >= 64, "Image is shorter than its ARM64 header")
    require(image[56:60] == b"ARM\x64", "Image has no raw ARM64 header")
    flags = struct.unpack_from("<Q", image, 24)[0]
    require(not flags & 1, "Big-endian Images are not supported by this KPM tool")
    page_shift = {0: None, 1: 12, 2: 14, 3: 16}[(flags >> 1) & 3]
    entry = 4 if image[:2] == b"MZ" else 0
    instruction = struct.unpack_from("<I", image, entry)[0]
    require(instruction & 0xFC000000 == 0x14000000, "ARM64 entry is not an unconditional B instruction")
    immediate = instruction & 0x3FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    target = entry + immediate * 4
    require(0 <= target and target + 4 <= len(image),
            f"ARM64 entry target {target:#x} is outside Image ({len(image):#x} bytes)")
    return {"entry": entry, "target": target, "flags": flags,
            "page_shift": page_shift, "memory_size": struct.unpack_from("<Q", image, 16)[0]}


def linux_banner(image):
    match = re.search(rb"Linux version \d+\.\d+\.\d+[^\x00\n]{0,4096}", image)
    require(match is not None, "Image has no Linux kernel version banner")
    return match.group(0)


def validate_images(original: bytes | None, patched: bytes) -> dict:
    header = arm64_header(patched)
    kp_offset = header["target"] - PAGE
    require(kp_offset >= 64 and kp_offset % PAGE == 0,
            "KPM entry does not point one page after an aligned loader header")
    require(kp_offset + PRESET_SIZE <= len(patched), "KPM preset is truncated")
    require(patched[kp_offset:kp_offset + 8] == b"KP1158\x00\x00",
            "ARM64 entry has no valid KPM payload header")
    version = patched[kp_offset + 8:kp_offset + 12]
    require(any(version[1:]), "KPM payload has an empty version (placeholder loader)")
    require(patched[kp_offset + 24:kp_offset + 48].strip(b"\x00 \t\r\n"),
            "KPM payload has no build timestamp")

    def field(offset):
        return struct.unpack_from("<q", patched, kp_offset + offset)[0]

    kimg_size = field(0x48)
    kpimg_size = field(0x50)
    kernel_size = field(0x58)
    page_shift = field(0x60)
    setup_offset = field(0x68)
    start_offset = field(0x70)
    extra_size = field(0x78)
    require(kimg_size >= 64 and (kimg_size + PAGE - 1) // PAGE * PAGE == kp_offset,
            "KPM preset original size does not match the loader location")
    require(setup_offset == kp_offset, "KPM setup offset does not match its header")
    require(kpimg_size >= PAGE + 4, "KPM payload is too small to contain its entry code")
    require(extra_size >= 0 and kp_offset + kpimg_size + extra_size <= len(patched),
            "KPM payload or extra data extends beyond Image")
    require(header["target"] + 4 <= kp_offset + kpimg_size,
            "ARM64 entry points outside the KPM payload")
    require(patched[header["target"]:header["target"] + 4] not in (bytes(4), b"\xff" * 4),
            "KPM entry contains no executable loader code")
    require(page_shift in (12, 14, 16), "KPM preset has an invalid page size")
    require(header["page_shift"] in (None, page_shift),
            "KPM page size differs from the ARM64 header")
    require(kernel_size >= kimg_size and start_offset >= max(kernel_size, kp_offset + kpimg_size + extra_size)
            and start_offset % PAGE == 0, "KPM runtime placement overlaps the kernel or payload")
    if header["memory_size"]:
        require(kernel_size == header["memory_size"], "KPM kernel memory size differs from the ARM64 header")
    banner = linux_banner(patched)

    if original is not None:
        original_header = arm64_header(original)
        require(len(original) == kimg_size, "KPM preset does not describe the original Image length")
        require(original_header["flags"] == header["flags"], "KPM changed the kernel flags/page size")
        require(original_header["memory_size"] == header["memory_size"], "KPM changed the kernel memory size")
        require(patched[kp_offset + 0xD0:kp_offset + 0xD8] == original[:8],
                "KPM saved entry does not match the original Image")
        require(linux_banner(original) == banner, "Patched Image has a different Linux kernel banner")

    return {"entry_target": header["target"], "kpimg_offset": kp_offset,
            "kpimg_size": kpimg_size, "original_size": kimg_size,
            "kpm_version": f"{version[3]}.{version[2]}.{version[1]}", "page_shift": page_shift}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--patched", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = validate_images(args.original.read_bytes(), args.patched.read_bytes())
    except (OSError, ValueError) as error:
        parser.exit(1, f"KPM image validation failed: {error}\n")
    print("KPM image structure verified: " + json.dumps(result, sort_keys=True))
    print("Structural checks do not establish device boot compatibility.")


if __name__ == "__main__":
    main()
