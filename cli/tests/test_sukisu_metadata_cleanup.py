"""Internal metadata cleanup must never delete kernel or APK artifacts."""

import importlib.util
import io
import json
from pathlib import Path
import unittest
from urllib.error import HTTPError, URLError


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cleanup_sukisu_metadata", ROOT / ".github/scripts/cleanup_sukisu_metadata.py")
CLEAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEAN)
RUN_ID = 40166227523


def metadata(artifact_id=1, name="SukiSU-Metadata-android14-6.1-138", run_id=RUN_ID):
    return {"id": artifact_id, "name": name, "workflow_run": {"id": run_id}}


class FakeAPI:
    def __init__(self, artifacts, missing=()):
        self.artifacts = artifacts
        self.deleted = []
        self.missing = missing

    def list_artifacts(self, run_id):
        return self.artifacts

    def delete_artifact(self, artifact_id):
        self.deleted.append(artifact_id)
        return artifact_id not in self.missing


class MetadataCleanupTests(unittest.TestCase):
    def test_default_preview_does_not_delete(self):
        api = FakeAPI([metadata()])
        result = CLEAN.cleanup_metadata(api, RUN_ID)
        self.assertEqual("preview", result["mode"])
        self.assertEqual([metadata()["name"]], [item["name"] for item in result["selected"]])
        self.assertEqual([], api.deleted)

    def test_only_exact_internal_names_are_deleted(self):
        retained = ("SukiSU_kernel-android14-6.1-138", "SukiSU-Manager(41075-6)",
                    "SukiSU_kernel-android14-6.1-138-Rejects", "susfs-module",
                    "SukiSU-Metadata-android14-6.1-138-Images",
                    "SukiSU-Metadata-android14-6.1-138/anything",
                    "SukiSU-Metadata-android14-6.1-138\n",
                    "SukiSU-Metadata-android14-6.1-138.apk",
                    "SukiSU-Metadata-android17-6.18-1")
        api = FakeAPI([metadata()] + [metadata(i + 2, name) for i, name in enumerate(retained)])
        result = CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual([1], api.deleted)
        self.assertEqual(1, result["deleted"])

    def test_all_current_series_and_lts_metadata_are_recognized(self):
        names = [f"SukiSU-Metadata-{android}-{kernel}-{sub}" for android, kernel, sub in (
            ("android12", "5.10", "236"), ("android13", "5.15", "194"),
            ("android14", "6.1", "138"), ("android15", "6.6", "57"),
            ("android16", "6.12", "69"), ("android14", "6.1", "X"))]
        result = CLEAN.select_metadata_artifacts([metadata(i + 1, name) for i, name in enumerate(names)], RUN_ID)
        self.assertEqual(names, [item["name"] for item in result])

    def test_wrong_run_aborts_entire_plan_before_any_deletion(self):
        api = FakeAPI([metadata(), metadata(2, run_id=RUN_ID + 1)])
        with self.assertRaisesRegex(CLEAN.CleanupError, "workflow run"):
            CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual([], api.deleted)

    def test_missing_provenance_is_allowed_only_on_scoped_listing(self):
        item = metadata()
        item.pop("workflow_run")
        self.assertEqual(1, len(CLEAN.select_metadata_artifacts([item], RUN_ID)))
        item["workflow_run"] = {}
        with self.assertRaises(CLEAN.CleanupError):
            CLEAN.select_metadata_artifacts([item], RUN_ID)

    def test_duplicates_do_not_cause_repeat_delete(self):
        api = FakeAPI([metadata(), metadata()])
        CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual([1], api.deleted)
        with self.assertRaisesRegex(CLEAN.CleanupError, "Conflicting"):
            CLEAN.select_metadata_artifacts([metadata(), metadata(name="SukiSU-Metadata-android15-6.6-57")], RUN_ID)

    def test_invalid_identifiers_fail_before_delete(self):
        for identifier in (0, -1, True, "1"):
            with self.subTest(identifier=identifier), self.assertRaises(CLEAN.CleanupError):
                CLEAN.select_metadata_artifacts([metadata(identifier)], RUN_ID)
        for repository in ("owner/../secret", "owner/repo?token=secret", "owner/..", "owner/repo\n"):
            with self.subTest(repository=repository), self.assertRaises(CLEAN.CleanupError):
                CLEAN.GitHubAPI(repository)

    def test_delete_404_is_counted_as_already_cleaned(self):
        api = FakeAPI([metadata()], missing={1})
        result = CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual(0, result["deleted"])
        self.assertEqual(1, result["already_missing"])

    def test_pagination_finishes_before_deletion_changes_the_list(self):
        original = [metadata(i + 1, f"SukiSU-Metadata-android14-6.1-{i + 1}") for i in range(101)]
        calls = []
        def open_request(request, timeout):
            calls.append(request)
            if request.method == "DELETE":
                original[:] = [item for item in original if item["id"] != int(request.full_url.rsplit("/", 1)[1])]
                return io.BytesIO()
            page = int(request.full_url.rsplit("page=", 1)[1])
            return io.BytesIO(json.dumps({"artifacts": original[(page - 1) * 100:page * 100]}).encode())
        api = CLEAN.GitHubAPI("cyzrqh/ABK", "fixture-secret", opener=open_request)
        result = CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual(101, result["deleted"])
        self.assertEqual(["GET", "GET", "DELETE"], [request.method for request in calls[:3]])
        self.assertIn(f"runs/{RUN_ID}/artifacts?per_page=100&page=1", calls[0].full_url)
        self.assertEqual([], original)

    def test_transient_errors_retry_and_delete_404_is_idempotent(self):
        responses = [HTTPError("https://api.github.com", 429, "busy", {"Retry-After": "200"}, None),
                     URLError("temporary connection failure"), io.BytesIO(b'{"artifacts": []}')]
        sleeps = []
        def open_request(request, timeout):
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        api = CLEAN.GitHubAPI("cyzrqh/ABK", opener=open_request, sleep=sleeps.append)
        self.assertEqual([], api.list_artifacts(RUN_ID))
        self.assertEqual([10, 2], sleeps)
        api.opener = lambda request, timeout: (_ for _ in ()).throw(
            HTTPError(request.full_url, 404, "missing", {}, None))
        self.assertFalse(api.delete_artifact(1))

    def test_permission_errors_are_bounded_and_do_not_leak_credentials(self):
        calls = []
        def open_request(request, timeout):
            calls.append(request)
            raise HTTPError(request.full_url, 403, "fixture-secret", {}, io.BytesIO(b"fixture-secret"))
        api = CLEAN.GitHubAPI("cyzrqh/ABK", "fixture-secret", opener=open_request)
        with self.assertRaises(CLEAN.CleanupError) as error:
            api.list_artifacts(RUN_ID)
        self.assertEqual(1, len(calls))
        self.assertNotIn("fixture-secret", str(error.exception))

    def test_pagination_failure_never_deletes_partial_results(self):
        calls = []
        def open_request(request, timeout):
            calls.append(request.method)
            page = int(request.full_url.rsplit("page=", 1)[1])
            return io.BytesIO(json.dumps({"artifacts": [metadata(i + 1) for i in range(100)] if page == 1 else "bad"}).encode())
        api = CLEAN.GitHubAPI("cyzrqh/ABK", opener=open_request)
        with self.assertRaises(CLEAN.CleanupError):
            CLEAN.cleanup_metadata(api, RUN_ID, apply=True)
        self.assertEqual(["GET", "GET"], calls)


if __name__ == "__main__":
    unittest.main()
