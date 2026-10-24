"""Keep kernel display metadata tied to the source used by the official APK."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "pin_sukisu_version", ROOT / ".github/scripts/pin_sukisu_version.py")
PIN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PIN)

# Both cf87 (UAPI 4) and b505 (UAPI 6) have these five final assignments.
KBUILD = '''VERSION_BASE := 40000
VERSION_OFFSET := 2815
GITHUB_COMMITS := $(shell curl remote-main)
KSU_GITHUB_VER := $(shell curl remote-release)
KSU_VERSION := $(GITHUB_COMMITS)
VERSION_TAG := $(KSU_GITHUB_VER)
KSU_VERSION_FULL := v$(VERSION_TAG)-unknown
obj-$(CONFIG_KPM) += extension/kpm/kpm.o
print:
\t@echo $(KSU_VERSION) $(KSU_VERSION_FULL)
'''


class SukisuVersionMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sukisu-version-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Version test")
        self.git("config", "user.email", "version-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.kbuild = self.root / "kernel/Kbuild"
        self.kbuild.parent.mkdir()
        self.kbuild.write_text(KBUILD, encoding="utf-8")
        (self.root / "uapi").mkdir()
        (self.root / "uapi/supercall.h").write_text(
            "static const unsigned KERNEL_SU_UAPI_VERSION = 6;\n", encoding="utf-8")
        (self.root / "kernel/Kconfig").write_text("config KPM\n\tbool\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "Source paired with manager")
        self.git("tag", "v4.2.1-r1")
        self.sha = self.git("rev-parse", "HEAD")
        # Remote/local main and its new tag have advanced past the selected source.
        (self.root / "later").write_text("new upstream source\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "New upstream version")
        self.git("tag", "v4.2.1-r2")
        self.git("checkout", "--detach", self.sha)

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], stderr=subprocess.PIPE,
            text=True, encoding="utf-8").strip()

    def test_detached_source_uses_manager_count_and_reachable_tag(self):
        data = PIN.pin_version(self.root)
        self.assertEqual(40000 + 1 - 2815, data["version"])
        self.assertEqual("4.2.1-r1", data["tag"])
        self.assertEqual(f'v4.2.1-r1-{self.sha[:8]}@HEAD', data["full"])
        text = self.kbuild.read_text(encoding="utf-8")
        self.assertNotIn("$(shell curl", text)
        self.assertIn(f'KSU_VERSION := {data["version"]}\n', text)

    def test_only_metadata_changes_and_second_pass_is_identical(self):
        PIN.pin_version(self.root)
        first = self.kbuild.read_bytes()
        PIN.pin_version(self.root)
        self.assertEqual(first, self.kbuild.read_bytes())
        self.assertEqual("kernel/Kbuild", self.git("diff", "--name-only"))
        self.assertIn(b"obj-$(CONFIG_KPM) += extension/kpm/kpm.o\n", first)

    def test_shallow_history_cannot_silently_report_wrong_version(self):
        (self.root / ".git/shallow").write_text(self.sha + "\n", encoding="ascii")
        before = self.kbuild.read_bytes()
        with self.assertRaisesRegex(ValueError, "history is shallow"):
            PIN.pin_version(self.root)
        self.assertEqual(before, self.kbuild.read_bytes())

    def test_untagged_source_uses_official_describe_fallback(self):
        self.git("tag", "-d", "v4.2.1-r1", "v4.2.1-r2")
        expected = self.git("describe", "--tags", "--always", "--abbrev=0")
        self.assertEqual(expected, PIN.pin_version(self.root)["tag"])

    def test_unknown_or_duplicate_assignments_fail_without_writing(self):
        for text in (KBUILD.replace("KSU_VERSION :=", "OTHER_VERSION :="),
                     KBUILD + "KSU_VERSION := 123\n"):
            with self.subTest(text=text):
                self.kbuild.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Unsupported SukiSU Kbuild"):
                    PIN.pin_version(self.root)
                self.assertEqual(text, self.kbuild.read_text(encoding="utf-8"))

    def test_custom_display_tag_is_preserved_without_make_injection(self):
        data = PIN.pin_version(self.root, "My_build")
        self.assertEqual(f'v4.2.1-r1-My_build@HEAD[{self.sha[:8]}]', data["full"])
        for tag in ("My build", "$(shell curl bad)", 'bad"tag', "bad\ntag"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                PIN.pin_version(self.root, tag)

    @unittest.skipUnless(shutil.which("make"), "GNU make is checked in Linux CI")
    def test_real_make_reports_same_source_metadata_without_network(self):
        data = PIN.pin_version(self.root)
        output = subprocess.check_output(
            ["make", "-s", "-f", str(self.kbuild), "print"],
            text=True, encoding="utf-8", timeout=10).strip()
        self.assertEqual(f'{data["version"]} {data["full"]}', output)


if __name__ == "__main__":
    unittest.main()
