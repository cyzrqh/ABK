"""Recover real kernel identities from logs without metadata download items."""

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "read_sukisu_run_metadata", ROOT / ".github/scripts/read_sukisu_run_metadata.py")
READ = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READ)
RUN_ID = 40166227523
HEAD = "1" * 40


def record(label="android14-6.1.138-2025-06", version=41075):
    return {"schema_version": 1, "kernel_label": label, "kernel_source_sha": "2" * 40,
            "version_code": version, "uapi": 6, "expected_certificate_sha256": "a" * 64,
            "expected_certificate_size": 860, "manager_package_name": "com.sukisu.ultra",
            "compiled_command_files_count": 38}


def log_line(value, marked=False):
    return ("2026-10-25T09:00:00.000Z " + (READ.MARKER if marked else "")
            + json.dumps(value) + "\n").encode()


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, payload in entries.items():
            bundle.writestr(name, payload)
    return stream.getvalue()


def job(number=1, label="android14-6.1.138-2025-06", **changes):
    android, full, year, month = label.split("-")
    result = {"id": number, "name": f"{full}-{android}-{year}-{month}-SukiSU",
              "run_id": RUN_ID, "head_sha": HEAD, "status": "completed", "conclusion": "success",
              "steps": [{"name": READ.STEP_NAME, "conclusion": "success"}]}
    result.update(changes)
    return result


class FakeAPI:
    repository = "cyzrqh/ABK"

    def __init__(self, *, status="completed", jobs=None, zip_payload=None, job_payloads=None):
        self.run = {"id": RUN_ID, "repository": {"full_name": self.repository},
                    "head_sha": HEAD, "status": status}
        self.job_records = jobs if jobs is not None else [job()]
        self.zip_payload = zip_payload if zip_payload is not None else archive({"kernel/identity.txt": log_line(record())})
        self.job_payloads = job_payloads if job_payloads is not None else {1: log_line(record())}
        self.downloads = []

    def document(self, suffix):
        return self.run

    def jobs(self, run_id):
        return self.job_records

    def download(self, suffix, maximum=READ.MAX_DOWNLOAD):
        self.downloads.append(suffix)
        if suffix.startswith("runs/"):
            return self.zip_payload
        return self.job_payloads[int(suffix.split("/")[1])]


class RunMetadataTests(unittest.TestCase):
    def test_completed_run_supports_legacy_and_marked_json_records(self):
        second = record("android15-6.6.57-2024-12")
        api = FakeAPI(jobs=[job(), job(2, second["kernel_label"])], zip_payload=archive({
            "first/step.txt": log_line(record()), "second/step.txt": log_line(second, True),
            "first/aggregate.txt": log_line(record())}))
        identity, records = READ.read_run_metadata(api, RUN_ID)
        self.assertEqual(2, len(records))
        self.assertEqual({"repository": "cyzrqh/abk", "run_id": RUN_ID, "head_sha": HEAD}, identity)
        self.assertEqual([f"runs/{RUN_ID}/logs"], api.downloads)

    def test_in_progress_run_reads_completed_kernel_jobs_not_its_own_logs(self):
        api = FakeAPI(status="in_progress")
        _, records = READ.read_run_metadata(api, RUN_ID)
        self.assertEqual({record()["kernel_label"]: record()}, records)
        self.assertEqual(["jobs/1/logs"], api.downloads)

    def test_completed_archive_missing_a_job_falls_back_to_that_job(self):
        api = FakeAPI(zip_payload=archive({"manager.txt": b"manager is running\n"}))
        _, records = READ.read_run_metadata(api, RUN_ID)
        self.assertEqual(1, len(records))
        self.assertEqual([f"runs/{RUN_ID}/logs", "jobs/1/logs"], api.downloads)

    def test_each_successful_job_must_supply_its_actual_record(self):
        for payload in (b"no identity\n", log_line(record("android15-6.6.57-2024-12"))):
            api = FakeAPI(status="in_progress", job_payloads={1: payload})
            with self.subTest(payload=payload), self.assertRaisesRegex(READ.MetadataError, "missing or unexpected"):
                READ.read_run_metadata(api, RUN_ID)

    def test_conflicting_records_are_rejected(self):
        payload = archive({"a.txt": log_line(record()), "b.txt": log_line(record(version=41076))})
        with self.assertRaisesRegex(READ.MetadataError, "Conflicting"):
            READ.records_from_zip(payload)

    def test_invalid_schema_types_and_zero_command_count_are_rejected(self):
        for change in ({"schema_version": 2}, {"schema_version": True},
                       {"compiled_command_files_count": 0}, {"version_code": "41075"},
                       {"uapi": True}, {"expected_certificate_size": 1}):
            value = dict(record(), **change)
            with self.subTest(change=change), self.assertRaises(READ.MetadataError):
                READ.records_from_stream(io.BytesIO(log_line(value)))

    def test_path_injection_in_label_or_zip_member_is_rejected(self):
        for label in ("../outside", "android14-6.1.138-2025-06/../../outside", "android14-6.1.138-2025-06\n"):
            with self.subTest(label=label), self.assertRaises(READ.MetadataError):
                READ.records_from_stream(io.BytesIO(log_line(record(label))))
        for name in ("../outside.txt", "/outside.txt", "C:/outside.txt"):
            with self.subTest(name=name), self.assertRaisesRegex(READ.MetadataError, "Unsafe path"):
                READ.records_from_zip(archive({name: log_line(record())}))
        # ZipInfo normalizes backslashes on Windows; replace both raw ZIP name
        # fields to exercise a genuinely unsafe archive identically on any OS.
        unsafe = archive({"a/outside.txt": log_line(record())}).replace(b"a/outside.txt", b"a\\outside.txt")
        with self.assertRaisesRegex(READ.MetadataError, "Unsafe path"):
            READ.records_from_zip(unsafe)

    def test_oversized_archives_entries_and_expansion_are_rejected(self):
        payload = archive({"a.txt": log_line(record())})
        for constant, maximum in (("MAX_DOWNLOAD", 1), ("MAX_LOG", 1), ("MAX_UNCOMPRESSED", 1), ("MAX_ENTRIES", 0)):
            with self.subTest(constant=constant), patch.object(READ, constant, maximum):
                with self.assertRaisesRegex(READ.MetadataError, "size limit"):
                    READ.records_from_zip(payload)

    def test_wrong_run_or_job_provenance_is_rejected(self):
        api = FakeAPI()
        api.run["repository"]["full_name"] = "someone/ABK"
        with self.assertRaisesRegex(READ.MetadataError, "provenance"):
            READ.read_run_metadata(api, RUN_ID)
        for changes in ({"run_id": RUN_ID + 1}, {"head_sha": "3" * 40}):
            with self.subTest(changes=changes), self.assertRaisesRegex(READ.MetadataError, "different workflow"):
                READ.read_run_metadata(FakeAPI(jobs=[job(**changes)]), RUN_ID)

    def test_failed_or_unrelated_jobs_do_not_create_manager_requirements(self):
        api = FakeAPI(jobs=[job(conclusion="failure"), job(steps=[])])
        with self.assertRaisesRegex(READ.MetadataError, "No successful kernel jobs"):
            READ.read_run_metadata(api, RUN_ID)

    def test_cache_is_bound_to_run_and_same_label_can_be_refreshed(self):
        identity = {"repository": "cyzrqh/ABK", "run_id": RUN_ID, "head_sha": HEAD}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            first = record()
            READ.write_records(output, identity, {first["kernel_label"]: first})
            second = record(version=41076)
            READ.write_records(output, identity, {second["kernel_label"]: second})
            self.assertEqual(41076, json.loads((output / (first["kernel_label"] + ".json")).read_text())["version_code"])
            with self.assertRaisesRegex(READ.MetadataError, "another workflow"):
                READ.write_records(output, dict(identity, run_id=RUN_ID + 1), {first["kernel_label"]: first})

    def test_unstamped_cache_and_symlink_like_output_names_are_not_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "old.json").write_text(json.dumps(record()))
            with self.assertRaisesRegex(READ.MetadataError, "lack workflow run provenance"):
                READ.write_records(output, {"run_id": RUN_ID}, {record()["kernel_label"]: record()})

    def test_redirects_strip_token_before_signed_storage_download(self):
        request = Request("https://api.github.com/logs", headers={"Authorization": "Bearer fixture-secret"})
        redirected = READ.SafeRedirect().redirect_request(
            request, None, 302, "Found", {}, "https://storage.example/signed-logs?key=public")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaisesRegex(READ.MetadataError, "non-HTTPS"):
            READ.SafeRedirect().redirect_request(request, None, 302, "Found", {}, "http://storage.example/logs")

    def test_network_retries_are_bounded_and_do_not_echo_secrets(self):
        calls, sleeps = [], []
        def opener(request, timeout):
            calls.append(request)
            raise HTTPError(request.full_url, 503, "fixture-secret", {}, io.BytesIO(b"fixture-secret"))
        api = READ.GitHubLogs("cyzrqh/ABK", "fixture-secret", opener=opener, sleep=sleeps.append)
        with self.assertRaises(READ.MetadataError) as error:
            api.download(f"jobs/1/logs")
        self.assertEqual(4, len(calls))
        self.assertEqual([1, 2, 4], sleeps)
        self.assertNotIn("fixture-secret", str(error.exception))

    def test_streamed_response_cannot_exceed_download_limit(self):
        api = READ.GitHubLogs("cyzrqh/ABK", opener=lambda request, timeout: io.BytesIO(b"123456"))
        with self.assertRaisesRegex(READ.MetadataError, "size limit"):
            api.download("jobs/1/logs", maximum=5)

    def test_pagination_reads_all_attempts_and_keeps_latest_successful_job(self):
        calls = []
        def opener(request, timeout):
            calls.append(request.full_url)
            page = int(request.full_url.rsplit("page=", 1)[1])
            batch = [job(i + 1) for i in range(100)] if page == 1 else [job(101)]
            return io.BytesIO(json.dumps({"jobs": batch}).encode())
        api = READ.GitHubLogs("cyzrqh/ABK", opener=opener)
        jobs = READ.successful_kernel_jobs(api.jobs(RUN_ID), RUN_ID, HEAD)
        self.assertEqual(101, jobs[record()["kernel_label"]]["id"])
        self.assertEqual(2, len(calls))
        self.assertIn("filter=all", calls[0])


if __name__ == "__main__":
    unittest.main()
