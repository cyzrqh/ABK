"""Read actual kernel compiler flags instead of re-querying a moving main."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "write_sukisu_build_metadata", ROOT / ".github/scripts/write_sukisu_build_metadata.py")
WRITER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRITER)
CERTIFICATE = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"


class SukisuBuildMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sukisu compiler metadata ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "kernel tree with spaces" / "KernelSU"
        (self.source / "uapi").mkdir(parents=True)
        (self.source / "uapi/supercall.h").write_text(
            "static const __u32 KERNEL_SU_UAPI_VERSION = 6;\n", encoding="utf-8")
        for args in (("init",), ("config", "user.name", "Metadata test"),
                     ("config", "user.email", "metadata@example.invalid"),
                     ("add", "."), ("commit", "-m", "Selected source")):
            subprocess.run(["git", "-C", str(self.source), *args], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.build = self.source.parent
        self.path = self.build / "out/common/drivers/kernelsu/core/.init.o.cmd"
        self.path.parent.mkdir(parents=True)

    def command(self, version=41068, package="com.sukisu.ultra", certificate=CERTIFICATE):
        return (f'cmd_drivers/kernelsu/core/init.o := clang -DKSU_VERSION={version} '
                f'-DEXPECTED_HASH=\\"{certificate}\\" -DEXPECTED_SIZE=0x35c '
                f'-DKSU_PACKAGE_NAME=\\"{package}\\" -c drivers/kernelsu/core/init.c\n')

    def collect(self):
        return WRITER.collect_metadata(self.source, self.build, "android12-5.10.236-2025-05")

    def test_version_and_signature_come_from_compiled_flags(self):
        self.path.write_text(self.command(), encoding="utf-8")
        result = self.collect()
        self.assertEqual(41068, result["version_code"])
        self.assertEqual(6, result["uapi"])
        self.assertEqual(CERTIFICATE, result["expected_certificate_sha256"])
        self.assertEqual(0x35c, result["expected_certificate_size"])
        self.assertEqual("com.sukisu.ultra", result["manager_package_name"])
        self.assertEqual(1, result["compiled_command_files_count"])
        expected_sha = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(expected_sha, result["kernel_source_sha"])

    def test_other_components_do_not_contaminate_sukisu_version(self):
        self.path.write_text(self.command(), encoding="utf-8")
        other = self.build / "out/common/drivers/other/.init.o.cmd"
        other.parent.mkdir(parents=True)
        other.write_text(self.command(123).replace("kernelsu", "other"), encoding="utf-8")
        self.assertEqual(41068, self.collect()["version_code"])

    def test_distinct_actual_versions_are_rejected(self):
        self.path.write_text(self.command(), encoding="utf-8")
        (self.path.parent / ".other.o.cmd").write_text(self.command(41069), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Expected one compiled SukiSU KSU_VERSION"):
            self.collect()

    def test_missing_compiled_signing_flags_cannot_fall_back_to_a_default(self):
        self.path.write_text(self.command().replace(f'-DEXPECTED_HASH=\\"{CERTIFICATE}\\" ', ""),
                             encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "EXPECTED_HASH"):
            self.collect()

    def test_missing_build_records_fail_without_inventing_a_version(self):
        with self.assertRaisesRegex(ValueError, "KSU_VERSION"):
            self.collect()

    def test_dependency_text_is_not_treated_as_a_compiler_command(self):
        self.path.write_text(self.command() + "deps_x := -DKSU_VERSION=123\n", encoding="utf-8")
        self.assertEqual(41068, self.collect()["version_code"])

    def test_savedcmd_and_real_source_path_are_supported(self):
        other = self.build / "out/objects/.init.o.cmd"
        other.parent.mkdir(parents=True)
        text = self.command().replace("cmd_", "savedcmd_", 1)
        text = text.replace("drivers/kernelsu", str(self.source / "kernel").replace("\\", "/"))
        other.write_text(text, encoding="utf-8")
        self.assertEqual(41068, self.collect()["version_code"])

    @unittest.skipIf(os.name == "nt", "Bazel output symlink traversal is checked on Linux")
    def test_bazel_output_symlink_outside_build_root_is_scanned_once(self):
        external = self.root / "bazel output outside workspace"
        command_path = external / "common/drivers/kernelsu/core/.init.o.cmd"
        command_path.parent.mkdir(parents=True)
        command_path.write_text(self.command(), encoding="utf-8")
        (self.build / "bazel-out").symlink_to(external, target_is_directory=True)
        result = self.collect()
        self.assertEqual(41068, result["version_code"])
        self.assertEqual(1, result["compiled_command_files_count"])

    def test_custom_compiled_package_and_certificate_are_kept(self):
        certificate = "a" * 64
        self.path.write_text(self.command(package="com.example.sukisu", certificate=certificate),
                             encoding="utf-8")
        result = self.collect()
        self.assertEqual(certificate, result["expected_certificate_sha256"])
        self.assertEqual("com.example.sukisu", result["manager_package_name"])

    def test_reading_metadata_never_changes_source_or_command_files(self):
        self.path.write_text(self.command(), encoding="utf-8")
        before = {path: path.read_bytes() for path in (self.path, self.source / "uapi/supercall.h")}
        self.collect()
        self.assertEqual(before, {path: path.read_bytes() for path in before})


if __name__ == "__main__":
    unittest.main()
