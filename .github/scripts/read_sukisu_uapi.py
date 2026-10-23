"""Read SukiSU's real interface version without modifying the source."""

import argparse
from pathlib import Path
import re


def read_uapi(root: Path) -> int:
    # Current trees share the root uapi/ via symlinks into kernel and manager.
    for relative in ("uapi/supercall.h", "kernel/include/uapi/supercall.h", "kernel/uapi/supercall.h"):
        path = root / relative
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            break
    else:
        raise ValueError("SukiSU UAPI header not found")
    versions = re.findall(
        r"(?m)^\s*(?:static\s+const\s+__u32\s+KERNEL_SU_UAPI_VERSION\s*=\s*"
        r"|#\s*define\s+KERNEL_SU_UAPI_VERSION\s+)(\d+)[uU]?\s*;?\s*$", text
    )
    if len(versions) != 1 or int(versions[0]) < 1:
        raise ValueError("Missing, ambiguous or unsupported SukiSU UAPI declaration")
    return int(versions[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        print(read_uapi(args.root))
    except (OSError, ValueError) as error:
        parser.exit(1, f"Cannot read SukiSU UAPI: {error}\n")
