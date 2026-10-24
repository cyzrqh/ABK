"""Keep pinned SukiSU kernels paired with their actual upstream manager build."""

import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / ".github/scripts/resolve-ksu-ref.sh"
DOWNLOADER = ROOT / ".github/scripts/download-manager-from-actions.sh"
SHA = "cf87e3f4ddd3f6e5464d85acf56aaa6950e70841"
REPO = "SukiSU-Ultra/SukiSU-Ultra"
POSIX = os.name != "nt" and all(shutil.which(t) for t in ("bash", "jq", "unzip"))

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
url = next(a for a in args if a.startswith("https://"))
with open(os.environ["SEEN"], "a") as stream:
    stream.write(url + "\n")
output = args[args.index("-o") + 1] if "-o" in args else None
if "/actions/workflows/" in url:
    run = 100 if "/build-manager.yml/" in url else 200
    data = {"workflow_runs": [{"id": run}]} if os.environ.get("EXACT", "yes") == "yes" else {"workflow_runs": []}
    print(json.dumps(data))
elif url.endswith("/artifacts"):
    print(os.environ["ARTIFACTS"])
elif "/actions/artifacts/" in url and url.endswith("/zip"):
    shutil.copyfile(os.environ["FIXTURE_ZIP"], output)
elif url.startswith("https://nightly.link/"):
    if url.rsplit("/", 1)[-1] != os.environ.get("NIGHTLY_NAME"):
        sys.exit(22)
    shutil.copyfile(os.environ["FIXTURE_ZIP"], output)
else:
    raise SystemExit("Unexpected request: " + url)
'''


class SukisuUapiReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sukisu-uapi-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location(
            "read_sukisu_uapi", ROOT / ".github/scripts/read_sukisu_uapi.py")
        self.reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.reader)

    def header(self, text, path="uapi/supercall.h"):
        header = self.root / path
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(text, encoding="utf-8")

    def test_real_cf87_root_header_uses_const_not_macro(self):
        self.header("static const __u32 KERNEL_SU_UAPI_VERSION = 4;\n")
        self.assertEqual(4, self.reader.read_uapi(self.root))

    def test_newer_interface_is_reported_honestly(self):
        self.header("static const __u32 KERNEL_SU_UAPI_VERSION = 6;\n")
        self.assertEqual(6, self.reader.read_uapi(self.root))

    def test_macro_layout_is_supported(self):
        self.header("#define KERNEL_SU_UAPI_VERSION 4\n", "kernel/uapi/supercall.h")
        self.assertEqual(4, self.reader.read_uapi(self.root))

    def test_missing_header_is_rejected(self):
        with self.assertRaises(ValueError):
            self.reader.read_uapi(self.root)

    def test_unknown_and_ambiguous_versions_are_rejected(self):
        for text in ("static const __u32 KERNEL_SU_UAPI_VERSION = OTHER;\n",
                     "#define KERNEL_SU_UAPI_VERSION 4\n#define KERNEL_SU_UAPI_VERSION 6\n"):
            with self.subTest(text=text):
                self.header(text)
                with self.assertRaises(ValueError):
                    self.reader.read_uapi(self.root)


class ManagerPairingContractTests(unittest.TestCase):
    def test_pairing_note_is_included_with_the_apk_artifact(self):
        workflow = (ROOT / ".github/workflows/get-manager.yml").read_text(encoding="utf-8")
        upload = workflow.split("- name: 上传APK", 1)[1].split("- name:", 1)[0]
        self.assertIn("manager-artifacts/${{ inputs.kernelsu_variant }}/*.apk", upload)
        self.assertIn("manager-artifacts/${{ inputs.kernelsu_variant }}/PAIRING.txt", upload)

    def test_sukisu_missing_exact_manager_cannot_fall_back_to_main(self):
        script = RESOLVER.read_text(encoding="utf-8")
        function = script.split("ksu_find_manager_run_id() {", 1)[1].split(
            'if [[ "${BASH_SOURCE[0]}"', 1
        )[0]
        guard = function.index('if [ "$repo" = "SukiSU-Ultra/SukiSU-Ultra" ]; then')
        fallback = function.index('ksu_workflow_run_id_for_branch "$repo"')
        self.assertLess(guard, fallback)
        self.assertIn("return 1", function[guard:fallback])
        self.assertIn("UAPI/KPM may be incompatible", function[guard:fallback])

    def test_only_normal_manager_artifact_names_are_accepted(self):
        script = DOWNLOADER.read_text(encoding="utf-8")
        self.assertIn('printf \'%s\\n\' "Manager" "manager"', script)
        self.assertNotIn('"Manager-spoofed"', script)
        self.assertNotIn('"Manager-gradle"', script)
        self.assertIn("select(.expired != true)", script)


@unittest.skipUnless(POSIX, "CI downloader requires POSIX bash, jq and unzip")
class ManagerPairingScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="manager-pairing-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        bindir = self.root / "bin"
        bindir.mkdir()
        curl = bindir / "curl"
        curl.write_text(FAKE_CURL, encoding="utf-8")
        curl.chmod(0o755)
        fixture = self.root / "manager.zip"
        with zipfile.ZipFile(fixture, "w") as archive:
            archive.writestr("SukiSU-matched.apk", b"APK fixture, not an installable app")
        self.env = dict(os.environ)
        self.env.update(PATH=f"{bindir}{os.pathsep}{self.env['PATH']}",
                        SEEN=str(self.root / "seen"), FIXTURE_ZIP=str(fixture),
                        GITHUB_TOKEN="fixture-token", GITHUB_REPOSITORY=REPO)
        self.destination = self.root / "output"

    def run_download(self, artifacts=(), **environment):
        self.env["ARTIFACTS"] = json.dumps({"artifacts": list(artifacts)})
        self.env.update(environment)
        return subprocess.run(["bash", str(DOWNLOADER), REPO, SHA, str(self.destination)],
                              env=self.env, text=True, capture_output=True, timeout=20)

    def urls(self):
        return (self.root / "seen").read_text(encoding="utf-8")

    def test_current_uppercase_official_manager_is_downloaded(self):
        result = self.run_download([{"name": "Manager", "id": 42, "expired": False}])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/artifacts/42/zip", self.urls())
        self.assertTrue((self.destination / "SukiSU-matched.apk").is_file())

    def test_legacy_lowercase_manager_still_downloads(self):
        result = self.run_download([{"name": "manager", "id": 43}])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/artifacts/43/zip", self.urls())

    def test_current_name_wins_and_spoofed_gradle_are_not_selected(self):
        result = self.run_download([{"name": name, "id": i} for i, name in enumerate(
            ("Manager-spoofed", "Manager-gradle", "manager", "Manager"), 1)])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/artifacts/4/zip", self.urls())
        self.assertNotIn("/actions/artifacts/1/zip", self.urls())

    def test_expired_current_name_uses_live_legacy_same_commit(self):
        result = self.run_download([{"name": "Manager", "id": 42, "expired": True},
                                    {"name": "manager", "id": 43, "expired": False}])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/artifacts/43/zip", self.urls())
        self.assertNotIn("/actions/artifacts/42/zip", self.urls())

    def test_nightly_accepts_current_name_for_the_same_run(self):
        result = self.run_download(NIGHTLY_NAME="Manager.zip")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/runs/100/Manager.zip", self.urls())

    def test_nightly_can_use_legacy_name_without_changing_commit(self):
        result = self.run_download(NIGHTLY_NAME="manager.zip")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("/actions/runs/100/Manager.zip", self.urls())
        self.assertIn("/actions/runs/100/manager.zip", self.urls())

    def test_missing_exact_commit_refuses_unrelated_manager(self):
        result = self.run_download(EXACT="no")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("UAPI/KPM may be incompatible", result.stderr)
        self.assertNotIn("branch=main", self.urls())
        self.assertFalse(self.destination.exists())

    def test_release_run_for_exact_commit_is_accepted(self):
        harness = r'''source "$1"
ksu_workflow_run_id_for_head_sha() {
  [[ "$2" == release.yml ]] && { echo 200; return 0; }
  return 1
}
ksu_workflow_run_id_for_branch() { echo UNEXPECTED; return 1; }
ksu_find_manager_run_id "$2" "$3" || exit 1
printf '%s %s' "$KSU_MANAGER_RUN_ID" "$MANAGER_RUN_SOURCE"
'''
        result = subprocess.run(["bash", "-c", harness, "test", str(RESOLVER), REPO, SHA],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("200 release", result.stdout)

    def test_other_variants_keep_existing_fallback(self):
        harness = r'''source "$1"
ksu_workflow_run_id_for_head_sha() { return 1; }
ksu_workflow_run_id_for_branch() { echo 300; }
ksu_find_manager_run_id tiann/KernelSU "$2" || exit 1
printf '%s %s' "$KSU_MANAGER_RUN_ID" "$MANAGER_RUN_FALLBACK_MAIN"
'''
        result = subprocess.run(["bash", "-c", harness, "test", str(RESOLVER), SHA],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("300 1", result.stdout)


if __name__ == "__main__":
    unittest.main()
