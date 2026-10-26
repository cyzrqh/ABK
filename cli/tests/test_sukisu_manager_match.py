"""Verify official APKs follow actual compiled versions without rewriting either."""

import importlib.util
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "match_sukisu_manager", ROOT / ".github/scripts/match_sukisu_manager.py")
MATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATCH)
CERTIFICATE_DER = b"Certificate fixture for verified Android tool output"
CERTIFICATE = hashlib.sha256(CERTIFICATE_DER).hexdigest()
CERTIFICATE_PEM = ("\n-----BEGIN CERTIFICATE-----\n" +
                   base64.b64encode(CERTIFICATE_DER).decode("ascii") +
                   "\n-----END CERTIFICATE-----\n")
APK_BYTES = b"APK fixture: these exact bytes must be preserved"


class MatchSukisuManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sukisu-manager-match-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "official-source"
        self.source.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Manager pairing test")
        self.git("config", "user.email", "manager@example.invalid")
        self.git("config", "core.autocrlf", "false")
        (self.source / "uapi").mkdir()
        self.header = self.source / "uapi/supercall.h"
        self.header.write_text("static const __u32 KERNEL_SU_UAPI_VERSION = 6;\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "Official source for signed manager")
        self.first = self.git("rev-parse", "HEAD")
        (self.source / "later").write_text("source update\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "Next manager version")
        self.second = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.second)
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        self.output = self.root / "managers"
        self.version = 40000 + 1 - 2815
        self.downloads = []
        self.download_candidates = []
        self.api_paths = []
        self.runs = [self.record(self.second, 2), self.record(self.first, 1)]
        self.jobs = self.manager_jobs(self.first, 1)
        self.write_kernel("first", self.version, "1" * 40)

    def git(self, *arguments):
        return MATCH.run_checked(["git", "-C", str(self.source), *arguments])

    def record(self, source, number, **changes):
        record = {"id": number, "head_sha": source, "head_branch": "main", "status": "completed",
                  "conclusion": "success", "event": "push", "created_at": f"2026-10-{number:02d}",
                  "head_repository": {"full_name": MATCH.OFFICIAL_REPO}}
        record.update(changes)
        return record

    def write_kernel(self, label, version, source, uapi=6, certificate=CERTIFICATE):
        (self.metadata / (label + ".json")).write_text(json.dumps({
            "schema_version": 1, "manager_package_name": "com.sukisu.ultra",
            "expected_certificate_size": len(CERTIFICATE_DER),
            "kernel_label": label, "kernel_source_sha": source, "version_code": version,
            "uapi": uapi, "expected_certificate_sha256": certificate}), encoding="utf-8")

    def api(self, path):
        self.api_paths.append(path)
        if "/jobs?" in path:
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        return {"workflow_runs": self.runs if "build-manager.yml" in path else []}

    def manager_jobs(self, source, run_id):
        return [{"id": run_id * 100 + 1, "run_id": run_id, "head_sha": source,
                 "name": "build-manager (false)", "status": "completed", "conclusion": "success"},
                {"id": run_id * 100 + 2, "run_id": run_id, "head_sha": source,
                 "name": "repack-manager (false)", "status": "completed", "conclusion": "success",
                 "steps": [{"name": "Upload build artifact", "status": "completed",
                            "conclusion": "success", "number": 12}]}]

    def download(self, candidate, directory):
        self.downloads.append(candidate["head_sha"])
        self.download_candidates.append(candidate)
        nested = directory / "nested"
        nested.mkdir()
        (nested / "manager.apk").write_bytes(APK_BYTES)

    def inspect(self, path):
        source = path.parents[1].name.removeprefix("download-")[:40]
        version = self.version + (source == self.second)
        return {"package_name": "com.sukisu.ultra", "version_code": version,
                "certificate_sha256": CERTIFICATE, "certificate_size": len(CERTIFICATE_DER)}

    def match(self, **changes):
        arguments = {"api_get": self.api, "downloader": self.download, "inspector": self.inspect}
        arguments.update(changes)
        return MATCH.match_managers(self.source, self.metadata, self.output, **arguments)

    def test_manager_follows_compiled_version_not_kernel_source(self):
        matches = self.match()
        self.assertEqual([self.first], self.downloads)
        self.assertEqual(self.version, matches[0]["version_code"])
        directory = self.output / f"{self.version}-6"
        self.assertEqual(APK_BYTES, (directory / "nested/manager.apk").read_bytes())
        note = (directory / "PAIRING.txt").read_text(encoding="utf-8")
        self.assertIn(self.first, note)
        self.assertIn("1" * 40, note)
        self.assertIn("not an exact-source pairing", note)
        self.assertEqual("", self.git("status", "--porcelain"))

    def test_matcher_passes_the_already_selected_official_run_to_downloader(self):
        self.match()
        self.assertEqual(1, len(self.download_candidates))
        candidate = self.download_candidates[0]
        self.assertEqual(1, candidate["id"])
        self.assertEqual(self.first, candidate["head_sha"])
        self.assertEqual("build-manager.yml", candidate["_workflow_file"])

    def test_cancelled_publishing_run_can_supply_its_successfully_built_uploaded_manager(self):
        self.runs = [self.record(self.first, 1, conclusion="cancelled")]
        matches = self.match()
        self.assertEqual(self.first, matches[0]["manager_source_sha"])
        jobs_paths = [path for path in self.api_paths if "/jobs?" in path]
        self.assertEqual(1, len(jobs_paths))
        self.assertIn("/actions/runs/1/jobs?filter=latest&per_page=100&page=1", jobs_paths[0])
        note = (self.output / f"{self.version}-6/PAIRING.txt").read_text(encoding="utf-8")
        self.assertIn("Official workflow conclusion: cancelled", note)
        self.assertIn("Verified successful build-manager (false) job: 101", note)
        self.assertEqual(APK_BYTES, (self.output / f"{self.version}-6/nested/manager.apk").read_bytes())

    def test_failed_publishing_run_can_supply_its_successfully_built_uploaded_manager(self):
        self.runs = [self.record(self.first, 1, conclusion="failure")]
        matches = self.match()
        self.assertEqual(self.first, matches[0]["manager_source_sha"])
        self.assertEqual(1, sum("/jobs?" in path for path in self.api_paths))

    def test_failed_normal_manager_build_is_rejected_even_when_an_apk_exists(self):
        self.runs = [self.record(self.first, 1, conclusion="failure")]
        self.jobs[0]["conclusion"] = "failure"
        with self.assertRaisesRegex(ValueError, "normal manager jobs successfully"):
            self.match()
        self.assertFalse(self.output.exists())

    def test_non_success_run_with_multiple_matched_apks_checks_jobs_only_once(self):
        self.write_kernel("new-version", self.version + 1, "2" * 40)
        self.runs = [self.record(self.first, 1, conclusion="cancelled")]
        def download(_candidate, directory):
            (directory / "first.apk").write_bytes(APK_BYTES)
            (directory / "second.apk").write_bytes(APK_BYTES)
        def inspect(path):
            return {"package_name": "com.sukisu.ultra",
                    "version_code": self.version + (path.name == "second.apk"),
                    "certificate_sha256": CERTIFICATE, "certificate_size": len(CERTIFICATE_DER)}
        self.assertEqual(2, len(self.match(downloader=download, inspector=inspect)))
        self.assertEqual(1, sum("/jobs?" in path for path in self.api_paths))

    def test_successful_run_needs_no_additional_manager_jobs_request(self):
        self.match()
        self.assertFalse(any("/jobs?" in path for path in self.api_paths))

    def test_non_success_run_jobs_are_not_queried_until_the_real_apk_matches(self):
        self.runs = [self.record(self.first, 1, conclusion="cancelled")]
        for changes in ({"version_code": self.version + 100},
                        {"certificate_sha256": "b" * 64},
                        {"certificate_size": len(CERTIFICATE_DER) + 1},
                        {"package_name": "com.sukisu.ultra.pr"}):
            with self.subTest(changes=changes):
                def inspect(_path):
                    return dict(package_name="com.sukisu.ultra", version_code=self.version,
                                certificate_sha256=CERTIFICATE,
                                certificate_size=len(CERTIFICATE_DER)) | changes
                with self.assertRaisesRegex(ValueError, "No verified official manager"):
                    self.match(inspector=inspect)
                self.assertFalse(any("/jobs?" in path for path in self.api_paths))
                self.assertFalse(self.output.exists())

    def test_non_success_run_requires_successful_normal_build_repack_and_upload(self):
        self.runs = [self.record(self.first, 1, conclusion="cancelled")]
        original = copy.deepcopy(self.jobs)
        cases = [(0, {"conclusion": "failure"}), (1, {"conclusion": "cancelled"}),
                 (1, {"status": "in_progress"}), (0, {"name": "build-manager (true)"}),
                 (1, {"name": "unknown-manager"}), (0, {"run_id": 999}),
                 (1, {"head_sha": "f" * 40}), (1, {"steps": []}),
                 (1, {"steps": [{"name": "Upload build artifact", "status": "completed",
                                 "conclusion": "failure"}]}),
                 (1, {"steps": [{"name": "Upload build artifact", "status": "in_progress",
                                 "conclusion": "success"}]})]
        for index, changes in cases:
            with self.subTest(index=index, changes=changes):
                self.jobs = copy.deepcopy(original)
                self.jobs[index].update(changes)
                with self.assertRaisesRegex(ValueError, "No verified official manager"):
                    self.match()
                self.assertFalse(self.output.exists())

    def test_cancelled_run_does_not_hide_successful_run_at_the_same_sha(self):
        self.runs = [self.record(self.first, 3, conclusion="cancelled"), self.record(self.first, 1)]
        # The newer cancelled run has no valid matching jobs; the older official
        # run at the same source must still be tried in its own download folder.
        self.jobs = []
        matches = self.match()
        self.assertEqual(self.first, matches[0]["manager_source_sha"])
        self.assertEqual([3, 1], [candidate["id"] for candidate in self.download_candidates])

    def test_non_success_release_and_in_progress_runs_are_excluded_before_download(self):
        for conclusion, status in (("cancelled", "completed"), ("failure", "completed"),
                                   ("success", "in_progress")):
            with self.subTest(conclusion=conclusion, status=status):
                def api(path):
                    return {"workflow_runs": [self.record(self.first, 1, head_branch="v4.2.1-r2",
                                                          conclusion=conclusion, status=status)]
                            if "release.yml" in path else []}
                with self.assertRaisesRegex(ValueError, "No verified official manager"):
                    self.match(api_get=api)
                self.assertEqual([], self.downloads)

    def test_non_success_candidates_keep_official_push_branch_and_repository_guards(self):
        for conclusion in ("cancelled", "failure"):
            for changes in ({"event": "pull_request"}, {"event": "pull_request_target"},
                            {"event": "workflow_dispatch"}, {"head_branch": "unknown-branch"},
                            {"head_repository": {"full_name": "fork/SukiSU-Ultra"}},
                            {"head_repository": None}):
                with self.subTest(conclusion=conclusion, changes=changes):
                    record = self.record(self.first, 1, conclusion=conclusion, **changes)
                    selected = MATCH.official_runs(lambda path: {
                        "workflow_runs": [record] if "build-manager.yml" in path else []})
                    self.assertEqual([], selected)

    def test_downloader_uses_known_run_without_reselecting_by_sha(self):
        candidate = dict(self.record(self.first, 123), _workflow_file="release.yml")
        with patch.object(MATCH.subprocess, "run") as download:
            download.return_value.stdout = ""
            MATCH.download_candidate(candidate, self.output)
        arguments = download.call_args.args[0]
        self.assertEqual([MATCH.OFFICIAL_REPO, self.first, str(self.output),
                          "--run-id", "123", "--workflow", "release.yml"], arguments[2:])
        self.assertTrue(download.call_args.kwargs["check"])
        self.assertTrue(download.call_args.kwargs["capture_output"])

    def test_known_run_candidate_rejects_invalid_ids_sources_and_workflows(self):
        candidate = dict(self.record(self.first, 123), _workflow_file="build-manager.yml")
        for changes in ({"id": 0}, {"id": -1}, {"id": True}, {"id": "123"},
                        {"head_sha": "main"}, {"_workflow_file": "unrelated.yml"}):
            with self.subTest(changes=changes), patch.object(MATCH.subprocess, "run") as download:
                with self.assertRaisesRegex(ValueError, "invalid source, run ID or workflow"):
                    MATCH.download_candidate(candidate | changes, self.output)
                download.assert_not_called()

    def test_one_apk_per_unique_version_interface_group(self):
        self.write_kernel("same-version", self.version, "2" * 40)
        self.write_kernel("new-version", self.version + 1, "3" * 40)
        matches = self.match()
        self.assertEqual(2, len(matches))
        self.assertEqual(2, len(self.downloads))
        note = (self.output / f"{self.version}-6/PAIRING.txt").read_text(encoding="utf-8")
        self.assertIn("first", note)
        self.assertIn("same-version", note)

    def test_missing_version_is_not_replaced_by_latest_manager(self):
        self.runs = [self.record(self.second, 2)]
        with self.assertRaisesRegex(ValueError, "No verified official manager"):
            self.match()
        self.assertEqual([self.second], self.downloads)
        self.assertFalse(self.output.exists())

    def test_official_dev_manager_can_follow_the_actual_kernel_version(self):
        self.runs = [self.record(self.first, 1, head_branch="dev")]
        matches = self.match()
        self.assertEqual(self.first, matches[0]["manager_source_sha"])
        self.assertNotIn("branch=main", self.api_paths[0])

    def test_published_manifest_version_is_authoritative_over_current_git_count(self):
        # Current history estimates first=v1, second=v2. A historical official
        # build can nevertheless publish second's APK as v1; try the real dev
        # APK instead of treating either estimate as an exact version contract.
        self.write_kernel("first", self.version + 1, "1" * 40)
        self.runs = [self.record(self.second, 2),
                     self.record(self.first, 1, head_branch="dev")]
        def inspect(path):
            source = path.parents[1].name.removeprefix("download-")[:40]
            return {"package_name": "com.sukisu.ultra",
                    "version_code": self.version + (source == self.first),
                    "certificate_sha256": CERTIFICATE,
                    "certificate_size": len(CERTIFICATE_DER)}
        matches = self.match(inspector=inspect)
        self.assertEqual([self.second, self.first], self.downloads)
        self.assertEqual(self.version + 1, matches[0]["version_code"])
        self.assertEqual(self.first, matches[0]["manager_source_sha"])

    def test_failed_apk_diagnostic_is_not_overwritten_by_old_header_failures(self):
        def inspect(path):
            raise subprocess.CalledProcessError(
                1, ["apksigner", "verify", str(path)], stderr="actual signature failure")
        self.runs += [self.record("f" * 40, 3)]
        def run(arguments):
            if any("f" * 40 in str(argument) for argument in arguments):
                raise subprocess.CalledProcessError(1, arguments, stderr="old header missing")
            return MATCH.run_checked(arguments)
        with self.assertRaisesRegex(ValueError, "actual signature failure"):
            self.match(inspector=inspect, run=run)

    def test_official_tag_release_can_supply_version_without_main_manager_run(self):
        paths = []
        def api(path):
            paths.append(path)
            if "release.yml" in path:
                return {"workflow_runs": [self.record(self.first, 1, head_branch="v4.2.1-r2")]}
            return {"workflow_runs": []}
        matches = self.match(api_get=api)
        self.assertEqual(self.first, matches[0]["manager_source_sha"])
        release_path = next(path for path in paths if "release.yml" in path)
        self.assertNotIn("branch=", release_path)

    def test_tag_release_outside_official_main_history_is_rejected(self):
        self.git("checkout", "--orphan", "unrelated-release")
        self.git("commit", "--allow-empty", "-m", "Not official main history")
        unrelated = self.git("rev-parse", "HEAD")
        def api(path):
            return {"workflow_runs": ([self.record(unrelated, 1, head_branch="v4.2.1-r2")]
                                      if "release.yml" in path else [])}
        with self.assertRaisesRegex(ValueError, "No verified official manager"):
            self.match(api_get=api)
        self.assertEqual([], self.downloads)

    def test_wrong_uapi_is_not_replaced_or_faked(self):
        self.write_kernel("first", self.version, "1" * 40, uapi=4)
        with self.assertRaisesRegex(ValueError, "No verified official manager"):
            self.match()
        self.assertEqual([], self.downloads)

    def test_wrong_real_manifest_version_signature_or_package_rejected(self):
        for changes in ({"version_code": self.version + 100},
                        {"certificate_sha256": "b" * 64},
                        {"certificate_size": len(CERTIFICATE_DER) + 1},
                        {"package_name": "com.sukisu.ultra.pr"}):
            with self.subTest(changes=changes):
                def inspect(_path):
                    return dict(package_name="com.sukisu.ultra", version_code=self.version,
                                certificate_sha256=CERTIFICATE,
                                certificate_size=len(CERTIFICATE_DER)) | changes
                with self.assertRaisesRegex(ValueError, "No verified official manager"):
                    self.match(inspector=inspect)
                self.assertFalse(self.output.exists())

    def test_one_missing_group_publishes_no_partial_manager_artifacts(self):
        self.write_kernel("unavailable", self.version + 999, "4" * 40)
        with self.assertRaisesRegex(ValueError, "No verified official manager"):
            self.match()
        self.assertFalse(self.output.exists())

    def test_conflicting_kernel_certificates_cannot_share_a_manager(self):
        self.write_kernel("different-certificate", self.version, "2" * 40, certificate="b" * 64)
        with self.assertRaisesRegex(ValueError, "different manager certificates"):
            self.match()
        self.assertEqual([], self.api_paths)

    def test_shallow_official_history_is_rejected_before_matching(self):
        (self.source / ".git/shallow").write_text(self.second + "\n", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "repository is shallow"):
            self.match()
        self.assertEqual([], self.api_paths)

    def test_existing_output_is_not_mixed_with_stale_apks(self):
        self.output.mkdir()
        (self.output / "old.apk").write_bytes(b"old")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            self.match()

    def test_pr_and_fork_runs_cannot_supply_an_official_manager(self):
        for changes in ({"event": "pull_request"}, {"head_branch": "unreviewed-feature"},
                        {"conclusion": "timed_out"},
                        {"id": 0}, {"id": -1}, {"id": True}, {"id": "123"},
                        {"head_repository": {"full_name": "someone/SukiSU-Ultra"}}):
            with self.subTest(changes=changes):
                self.runs = [self.record(self.first, 1, **changes)]
                with self.assertRaisesRegex(ValueError, "No verified official manager"):
                    self.match()

    def test_search_is_bounded_to_200_workflow_records(self):
        calls = []
        def api(path):
            calls.append(path)
            return {"workflow_runs": [self.record(self.first, number) for number in range(1, 101)]}
        self.assertEqual(100, len(MATCH.official_runs(api)))
        self.assertEqual(2, len(calls))
        self.assertTrue(all("status=completed" in path for path in calls))

    def test_jobs_verification_paginates_latest_attempt_and_stops_at_200(self):
        candidate = dict(self.record(self.first, 1, conclusion="cancelled"),
                         _workflow_file="build-manager.yml")
        padding = [{"id": number, "name": "other-job", "run_id": 1, "head_sha": self.first}
                   for number in range(100)]
        paths = []
        def api(path):
            paths.append(path)
            batch = padding if path.endswith("page=1") else self.jobs
            return {"jobs": batch, "total_count": 102}
        self.assertEqual({"build-manager": 101, "repack-manager": 102},
                         MATCH.verify_manager_jobs(candidate, api))
        self.assertEqual(2, len(paths))
        self.assertTrue(paths[-1].endswith("page=2"))
        with self.assertRaisesRegex(ValueError, "200-job verification limit"):
            MATCH.verify_manager_jobs(candidate, lambda _path: {"jobs": padding, "total_count": 201})

    def test_pagination_keeps_constant_page_size_when_other_workflow_ends(self):
        calls = []
        def api(path):
            calls.append(path)
            if "release.yml" in path:
                return {"workflow_runs": []}
            return {"workflow_runs": [self.record(self.first, number) for number in range(1, 101)]}
        MATCH.official_runs(api, max_runs=150)
        self.assertEqual(3, len(calls))
        self.assertIn("per_page=100&page=2", calls[-1])

    def test_scoped_token_denial_retries_same_public_official_endpoint(self):
        requests = []
        def open_url(request, timeout):
            requests.append(request)
            if request.get_header("Authorization"):
                raise HTTPError(request.full_url, 403, "Repository scoped token", {}, None)
            return io.BytesIO(b'{"workflow_runs": []}')
        path = "/repos/" + MATCH.OFFICIAL_REPO + "/actions/workflows/build-manager.yml/runs"
        with patch.dict(os.environ, {"GITHUB_TOKEN": "fixture-secret"}), patch.object(MATCH, "urlopen", open_url):
            self.assertEqual({"workflow_runs": []}, MATCH.github_api(path))
        self.assertEqual(2, len(requests))
        self.assertEqual(requests[0].full_url, requests[1].full_url)
        self.assertEqual("Bearer fixture-secret", requests[0].get_header("Authorization"))
        self.assertIsNone(requests[1].get_header("Authorization"))

    def test_transient_api_rate_limit_and_server_failure_back_off_on_same_url(self):
        path = "/repos/" + MATCH.OFFICIAL_REPO + "/actions/workflows/build-manager.yml/runs"
        for code, headers, expected_delay in ((429, {"Retry-After": "3"}, 3),
                                              (403, {"X-RateLimit-Remaining": "0"}, 2),
                                              (503, {}, 2)):
            with self.subTest(code=code):
                requests = []
                def open_url(request, timeout):
                    requests.append(request)
                    if len(requests) == 1:
                        raise HTTPError(request.full_url, code, "Try later", headers, None)
                    return io.BytesIO(b'{"workflow_runs": []}')
                with patch.dict(os.environ, {"GITHUB_TOKEN": "fixture-secret"}), \
                        patch.object(MATCH, "urlopen", open_url), patch.object(MATCH.time, "sleep") as sleep:
                    self.assertEqual({"workflow_runs": []}, MATCH.github_api(path))
                self.assertEqual(["https://api.github.com" + path] * 2,
                                 [request.full_url for request in requests])
                self.assertTrue(all(request.get_header("Authorization") for request in requests))
                sleep.assert_called_once_with(expected_delay)

    def test_api_transient_failure_retries_are_bounded(self):
        failure = HTTPError("https://api.github.com/test", 429, "Try later", {}, None)
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}), \
                patch.object(MATCH, "urlopen", side_effect=failure) as request, \
                patch.object(MATCH.time, "sleep") as sleep:
            with self.assertRaises(HTTPError):
                MATCH.github_api("/test")
        self.assertEqual(3, request.call_count)
        self.assertEqual([2, 4], [call.args[0] for call in sleep.call_args_list])

    def test_api_http_error_without_headers_keeps_its_original_error(self):
        failure = HTTPError("https://api.github.com/test", 404, "Not found", None, None)
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}), \
                patch.object(MATCH, "urlopen", side_effect=failure) as request:
            with self.assertRaises(HTTPError) as raised:
                MATCH.github_api("/test")
        self.assertIs(failure, raised.exception)
        self.assertEqual(1, request.call_count)

    def test_api_missing_endpoint_and_long_server_wait_are_not_retried(self):
        for code, headers in ((404, {}), (429, {"Retry-After": "60"}),
                              (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060"})):
            with self.subTest(code=code, headers=headers), \
                    patch.dict(os.environ, {"GITHUB_TOKEN": ""}), \
                    patch.object(MATCH, "urlopen", side_effect=HTTPError(
                        "https://api.github.com/test", code, "Unavailable", headers, None)) as request, \
                    patch.object(MATCH.time, "time", return_value=1000), \
                    patch.object(MATCH.time, "sleep") as sleep:
                with self.assertRaises(HTTPError):
                    MATCH.github_api("/test")
                self.assertEqual(1, request.call_count)
                sleep.assert_not_called()

    def test_apk_inspector_checks_manifest_and_real_signer(self):
        calls = []
        def run(arguments):
            calls.append(arguments)
            if "badging" in arguments:
                return "package: name='com.sukisu.ultra' versionCode='41068' versionName='v4.2.1'\n"
            return "Verifies\nSigner #1 certificate SHA-256 digest: " + CERTIFICATE + CERTIFICATE_PEM
        with patch.object(MATCH, "find_android_tool", side_effect=lambda name: name):
            identity = MATCH.inspect_apk(Path("official.apk"), run)
        self.assertEqual(41068, identity["version_code"])
        self.assertEqual(len(CERTIFICATE_DER), identity["certificate_size"])
        self.assertIn(["apksigner", "verify", "--print-certs-pem", "--verbose", "official.apk"], calls)

    def test_pem_bytes_must_match_verified_signer_hash(self):
        def run(arguments):
            if "badging" in arguments:
                return "package: name='com.sukisu.ultra' versionCode='41068'"
            return "Signer #1 certificate SHA-256 digest: " + "b" * 64 + CERTIFICATE_PEM
        with patch.object(MATCH, "find_android_tool", side_effect=lambda name: name):
            with self.assertRaisesRegex(ValueError, "PEM output"):
                MATCH.inspect_apk(Path("official.apk"), run)

    def test_invalid_or_multiple_signing_certificates_are_rejected(self):
        for signer in ("not a signer", "Signer #1 certificate SHA-256 digest: " + CERTIFICATE +
                       "\nSigner #2 certificate SHA-256 digest: " + "b" * 64):
            def run(arguments):
                return ("package: name='com.sukisu.ultra' versionCode='41068'"
                        if "badging" in arguments else signer)
            with self.subTest(signer=signer), patch.object(MATCH, "find_android_tool", side_effect=lambda name: name):
                with self.assertRaisesRegex(ValueError, "one verified official signing certificate"):
                    MATCH.inspect_apk(Path("official.apk"), run)

    def test_outputs_describe_all_verified_version_groups(self):
        matches = [{"version_code": 41068, "uapi": 6, "manager_source_sha": self.first,
                    "kernels": ["5.10"]},
                   {"version_code": 41069, "uapi": 6, "manager_source_sha": self.second,
                    "kernels": ["6.1"]}]
        environment = {name: str(self.root / name) for name in
                       ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY")}
        with patch.dict(os.environ, environment):
            MATCH.publish_summary(matches)
        self.assertIn("SUKISU_MANAGER_VERSIONS=41068-6_41069-6", Path(environment["GITHUB_ENV"]).read_text())
        self.assertIn("kversion=41068,41069", Path(environment["GITHUB_OUTPUT"]).read_text())


if __name__ == "__main__":
    unittest.main()
