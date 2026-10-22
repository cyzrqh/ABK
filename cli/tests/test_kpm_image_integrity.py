"""Reject structurally broken KPM images before they can enter an AK3 ZIP.

Fixtures follow the public KernelPatch 0.13.0 ARM64 preset layout, not a
device image or a downloaded executable.  These checks establish structural
integrity only; they cannot demonstrate that a kernel boots on real hardware.
"""

import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/validate_kpm_image.py"

# https://github.com/SukiSU-Ultra/SukiSU_KernelPatch_patch/blob/0.13.0/tools/preset.h
KP_HEADER_SIZE = 0x40
SETUP_KIMG_SIZE = 8
SETUP_KPIMG_SIZE = 16
SETUP_KERNEL_SIZE = 24
SETUP_PAGE_SHIFT = 32
SETUP_SETUP_OFFSET = 40
SETUP_START_OFFSET = 48
SETUP_EXTRA_SIZE = 56
SETUP_HEADER_BACKUP = 144  # 13 uint64 fields, then five map-symbol pointers.
KERNEL_LENGTH = 0x6230  # Intentionally not page-aligned, as in real builds.
KERNEL_MEMORY_SIZE = 0x10000  # Includes a BSS region absent from the file.
KP_OFFSET = 0x7000
KP_LENGTH = 0x6000
EXTRA_LENGTH = 0x80
BANNER = b"Linux version 6.1.138-android14-11-test (builder@host) #1 SMP\x00"


def branch_to(image: bytearray, offset: int, target: int) -> None:
    """Encode an ARM64 B instruction, including backwards branches."""
    delta = target - offset
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError("fixture branch target is not encodable")
    struct.pack_into("<I", image, offset, 0x14000000 | ((delta // 4) & 0x3FFFFFF))


def setup_u64(image: bytearray, field: int, value: int) -> None:
    struct.pack_into("<Q", image, KP_OFFSET + KP_HEADER_SIZE + field, value)


def make_images(efi: bool = True) -> tuple[bytes, bytes]:
    """Construct an original Image and its minimally valid 0.13.0 output."""
    original = bytearray(KERNEL_LENGTH)
    if efi:
        original[:4] = b"MZ\x40\xfa"
    entry_offset = 4 if efi else 0
    branch_to(original, entry_offset, 0x1000)
    struct.pack_into("<QQQ", original, 8, 0, KERNEL_MEMORY_SIZE, 0xA)
    original[56:60] = b"ARM\x64"
    original[0x1800:0x1800 + len(BANNER)] = BANNER
    original[0x1000:0x1008] = bytes.fromhex("1f2003d5c0035fd6")  # NOP; RET.

    patched = bytearray(original)
    patched.extend(bytes(KP_OFFSET + KP_LENGTH + EXTRA_LENGTH - len(patched)))
    branch_to(patched, entry_offset, KP_OFFSET + 0x1000)
    patched[KP_OFFSET:KP_OFFSET + 8] = b"KP1158\x00\x00"
    # version_t contains reserved, patch, minor, major, in that byte order.
    patched[KP_OFFSET + 8:KP_OFFSET + 12] = b"\x00\x00\x0d\x00"
    struct.pack_into("<Q", patched, KP_OFFSET + 16, 2)  # CONFIG_ANDROID.
    stamp = b"14:20:36 Jan 30 2026\x00"
    patched[KP_OFFSET + 24:KP_OFFSET + 24 + len(stamp)] = stamp
    # setup.kernel_version uses the same version_t representation.
    patched[KP_OFFSET + KP_HEADER_SIZE:KP_OFFSET + KP_HEADER_SIZE + 4] = (
        bytes((0, 138, 1, 6))
    )
    for field, value in (
        (SETUP_KIMG_SIZE, len(original)),
        (SETUP_KPIMG_SIZE, KP_LENGTH),
        (SETUP_KERNEL_SIZE, KERNEL_MEMORY_SIZE),
        (SETUP_PAGE_SHIFT, 12),
        (SETUP_SETUP_OFFSET, KP_OFFSET),
        (SETUP_START_OFFSET, KERNEL_MEMORY_SIZE),
        (SETUP_EXTRA_SIZE, EXTRA_LENGTH),
        (64, 0x3000),  # map_offset.
        (72, 0x800),  # map_max_size.
        (80, 0x2000),  # kallsyms_lookup_name_offset.
        (88, 0x2100),  # paging_init_offset.
        (96, 0x2200),  # printk_offset.
    ):
        setup_u64(patched, field, value)
    backup = KP_OFFSET + KP_HEADER_SIZE + SETUP_HEADER_BACKUP
    patched[backup:backup + 8] = original[:8]
    patched[KP_OFFSET + 0x1000:KP_OFFSET + 0x1008] = bytes.fromhex(
        "1f2003d5c0035fd6"
    )
    return bytes(original), bytes(patched)


class KpmImageIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("validate_kpm_image", SCRIPT)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot import {SCRIPT}")
        cls.validator = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.validator
        spec.loader.exec_module(cls.validator)

    def assert_invalid(self, original: bytes | None, patched: bytes) -> None:
        with self.assertRaises(ValueError):
            self.validator.validate_images(original, patched)

    def test_valid_efi_and_raw_arm64_entries(self) -> None:
        for efi in (True, False):
            with self.subTest(efi=efi):
                original, patched = make_images(efi)
                self.assertIsInstance(self.validator.validate_images(original, patched), dict)

    def test_valid_patched_image_can_be_checked_without_original(self) -> None:
        for efi in (True, False):
            with self.subTest(efi=efi):
                _, patched = make_images(efi)
                self.assertIsInstance(self.validator.validate_images(None, patched), dict)

    def test_non_page_aligned_original_and_bss_are_supported(self) -> None:
        original, patched = make_images()
        self.assertNotEqual(len(original) % 0x1000, 0)
        self.assertGreater(KERNEL_MEMORY_SIZE, len(patched))
        self.assertIsInstance(self.validator.validate_images(original, patched), dict)

    def test_runtime_memory_smaller_than_file_is_supported(self) -> None:
        original, patched = make_images()
        original = bytearray(original)
        patched = bytearray(patched)
        memory_size = 0x6000  # Valid 5.10-style tail beyond runtime memory.
        struct.pack_into("<Q", original, 16, memory_size)
        struct.pack_into("<Q", patched, 16, memory_size)
        setup_u64(patched, SETUP_KERNEL_SIZE, memory_size)
        setup_u64(patched, SETUP_START_OFFSET, 0xE000)
        self.assertLess(memory_size, len(original))
        self.assertIsInstance(self.validator.validate_images(bytes(original), bytes(patched)), dict)

    def test_runtime_placement_must_clear_both_memory_and_file_payload(self) -> None:
        original, patched = make_images()
        for start in (0x6000, 0xD000, 0xF000):
            with self.subTest(start=hex(start)):
                broken = bytearray(patched)
                setup_u64(broken, SETUP_START_OFFSET, start)
                self.assert_invalid(original, bytes(broken))

    def test_too_short_or_empty_image_is_rejected(self) -> None:
        original, patched = make_images()
        for short in (b"", patched[:4], patched[:63]):
            with self.subTest(length=len(short)):
                self.assert_invalid(original, short)

    def test_arm64_magic_is_required(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        broken[56:60] = b"FAKE"
        self.assert_invalid(original, bytes(broken))

    def test_entry_must_be_a_branch(self) -> None:
        for efi in (True, False):
            with self.subTest(efi=efi):
                original, patched = make_images(efi)
                broken = bytearray(patched)
                struct.pack_into("<I", broken, 4 if efi else 0, 0xD503201F)
                self.assert_invalid(original, bytes(broken))

    def test_entry_at_or_after_eof_is_rejected(self) -> None:
        original, patched = make_images()
        for target in (len(patched), len(patched) + 0x1000):
            with self.subTest(target=hex(target)):
                broken = bytearray(patched)
                branch_to(broken, 4, target)
                self.assert_invalid(original, bytes(broken))

    def test_negative_branch_target_is_rejected(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        branch_to(broken, 4, -0x1000)
        self.assert_invalid(original, bytes(broken))

    def test_real_failure_shape_single_aa_byte_with_out_of_file_entry(self) -> None:
        original, _ = make_images()
        # Broken upstream wrapper decrypts its one-byte 00 placeholder to AA;
        # kptools pads it to 16 bytes and appends a 128-byte empty extra item.
        broken = bytearray(original)
        broken.extend(bytes(KP_OFFSET + 0x10 + EXTRA_LENGTH - len(broken)))
        broken[KP_OFFSET] = 0xAA
        branch_to(broken, 4, KP_OFFSET + 0x1000)
        self.assert_invalid(original, bytes(broken))
        self.assert_invalid(None, bytes(broken))

    def test_kpm_header_magic_is_required(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        broken[KP_OFFSET:KP_OFFSET + 8] = b"\xaa" + bytes(7)
        self.assert_invalid(original, bytes(broken))

    def test_unrelated_later_magic_does_not_hide_bad_loader_header(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        broken[KP_OFFSET:KP_OFFSET + 8] = bytes(8)
        broken[KP_OFFSET + 0x2000:KP_OFFSET + 0x2008] = b"KP1158\x00\x00"
        self.assert_invalid(original, bytes(broken))

    def test_zero_kpm_version_is_rejected(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        broken[KP_OFFSET + 8:KP_OFFSET + 12] = bytes(4)
        self.assert_invalid(original, bytes(broken))

    def test_tiny_payload_size_is_rejected_even_with_a_plausible_header(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        setup_u64(broken, SETUP_KPIMG_SIZE, 0x10)
        self.assert_invalid(original, bytes(broken))

    def test_payload_size_cannot_exceed_the_file(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        setup_u64(broken, SETUP_KPIMG_SIZE, len(patched))
        self.assert_invalid(original, bytes(broken))

    def test_truncated_loader_or_extra_data_is_rejected(self) -> None:
        original, patched = make_images()
        for end in (KP_OFFSET + 0x1000, KP_OFFSET + KP_LENGTH - 1, len(patched) - 1):
            with self.subTest(end=hex(end)):
                self.assert_invalid(original, patched[:end])

    def test_recorded_setup_offset_must_match_the_actual_header(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        setup_u64(broken, SETUP_SETUP_OFFSET, KP_OFFSET + 0x1000)
        self.assert_invalid(original, bytes(broken))

    def test_recorded_original_size_must_not_overlap_the_loader(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        setup_u64(broken, SETUP_KIMG_SIZE, KP_OFFSET + 1)
        self.assert_invalid(None, bytes(broken))

    def test_original_length_must_match_preset(self) -> None:
        original, patched = make_images()
        self.assert_invalid(original + bytes(16), patched)

    def test_original_must_itself_have_a_valid_arm64_header(self) -> None:
        original, patched = make_images()
        broken = bytearray(original)
        broken[56:60] = bytes(4)
        self.assert_invalid(bytes(broken), patched)

    def test_original_banner_must_match_patched_kernel(self) -> None:
        original, patched = make_images()
        different = bytearray(original)
        banner_offset = original.index(b"6.1.138-android14")
        different[banner_offset:banner_offset + len(b"6.1.138-android14")] = (
            b"6.1.139-android14"
        )
        self.assert_invalid(bytes(different), patched)

    def test_original_page_size_must_match_patched_kernel(self) -> None:
        original, patched = make_images()
        different = bytearray(original)
        struct.pack_into("<Q", different, 24, 0xC)  # 16 KiB instead of 4 KiB.
        self.assert_invalid(bytes(different), patched)

    def test_preset_page_shift_must_match_arm64_header(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        setup_u64(broken, SETUP_PAGE_SHIFT, 14)
        self.assert_invalid(original, bytes(broken))

    def test_validation_is_repeatable_without_mutating_inputs(self) -> None:
        original, patched = make_images()
        before = (hashlib.sha256(original).digest(), hashlib.sha256(patched).digest())
        first = self.validator.validate_images(original, patched)
        second = self.validator.validate_images(original, patched)
        self.assertEqual(first, second)
        self.assertEqual(before, (
            hashlib.sha256(original).digest(), hashlib.sha256(patched).digest()
        ))

    def test_cli_validation_never_changes_either_file(self) -> None:
        original, patched = make_images()
        with tempfile.TemporaryDirectory(prefix="abk-kpm-integrity-") as folder:
            original_path = Path(folder) / "original-Image"
            patched_path = Path(folder) / "patched-Image"
            original_path.write_bytes(original)
            patched_path.write_bytes(patched)
            command = [sys.executable, str(SCRIPT), "--original", str(original_path),
                       "--patched", str(patched_path)]
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(original_path.read_bytes(), original)
                self.assertEqual(patched_path.read_bytes(), patched)

    def test_cli_failure_never_changes_either_file(self) -> None:
        original, patched = make_images()
        broken = bytearray(patched)
        branch_to(broken, 4, len(broken) + 0x1000)
        with tempfile.TemporaryDirectory(prefix="abk-kpm-integrity-") as folder:
            original_path = Path(folder) / "original-Image"
            patched_path = Path(folder) / "patched-Image"
            original_path.write_bytes(original)
            patched_path.write_bytes(broken)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--original", str(original_path),
                 "--patched", str(patched_path)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(original_path.read_bytes(), original)
            self.assertEqual(patched_path.read_bytes(), bytes(broken))

    def test_cli_requires_a_patched_image_argument(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=20
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
