#!/usr/bin/env python3
"""Read compiled SukiSU identities from run logs without publishing artifacts."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile


STEP_NAME = "记录内核实际编译的 SukiSU 管理器要求"
MARKER = "ABK_SUKISU_METADATA_JSON:"
MAX_DOWNLOAD = 256 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
MAX_UNCOMPRESSED = 1024 * 1024 * 1024
MAX_ENTRIES = 20000
FIELDS = ("schema_version", "kernel_label", "kernel_source_sha", "version_code", "uapi",
          "expected_certificate_sha256", "expected_certificate_size", "manager_package_name",
          "compiled_command_files_count")
LABEL = re.compile(r"android1[2-6]-(?:5\.10|5\.15|6\.1|6\.6|6\.12)\.(?:[0-9]+|X)-(?:[0-9]{4}-(?:0[1-9]|1[0-2])|lts)")
JOB_LABEL = re.compile(r"(?P<kernel>(?:5\.10|5\.15|6\.1|6\.6|6\.12)\.(?:[0-9]+|X))-(?P<android>android1[2-6])-(?P<patch>[0-9]{4}-(?:0[1-9]|1[0-2])|lts)")


class MetadataError(RuntimeError):
    pass


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if urlparse(new_url).scheme != "https":
            raise MetadataError("Refusing a non-HTTPS log download redirect")
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if redirected is not None and urlparse(new_url).netloc != urlparse(request.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHubLogs:
    def __init__(self, repository, token="", *, opener=None, sleep=time.sleep):
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]+", repository)
                or repository.rsplit("/", 1)[1] in {".", ".."}):
            raise MetadataError("Invalid repository")
        self.repository, self.token, self.sleep = repository, token, sleep
        self.opener = opener or build_opener(SafeRedirect()).open

    def download(self, suffix, maximum=MAX_DOWNLOAD):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "ABK-log-metadata"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        url = f"https://api.github.com/repos/{self.repository}/actions/{suffix}"
        for attempt in range(4):
            try:
                with self.opener(Request(url, headers=headers), timeout=45) as response:
                    content_length = response.headers.get("Content-Length") if hasattr(response, "headers") else None
                    if content_length and content_length.isdigit() and int(content_length) > maximum:
                        raise MetadataError("GitHub log response exceeds the size limit")
                    chunks, total = [], 0
                    while True:
                        chunk = response.read(min(1024 * 1024, maximum - total + 1))
                        if not chunk:
                            return b"".join(chunks)
                        total += len(chunk)
                        if total > maximum:
                            raise MetadataError("GitHub log response exceeds the size limit")
                        chunks.append(chunk)
            except HTTPError as error:
                retry_after = error.headers.get("Retry-After") if error.headers else None
                limited = error.code == 403 and error.headers and (
                    error.headers.get("X-RateLimit-Remaining") == "0" or retry_after)
                if attempt == 3 or not (error.code == 429 or 500 <= error.code <= 599 or limited):
                    raise MetadataError(f"GitHub log request failed (HTTP {error.code})") from None
                delay = min(10, max(1, int(retry_after))) if retry_after and retry_after.isdigit() else 2 ** attempt
            except (URLError, TimeoutError, ConnectionError):
                if attempt == 3:
                    raise MetadataError("GitHub log request failed after connection retries") from None
                delay = 2 ** attempt
            self.sleep(delay)
        raise MetadataError("GitHub log request did not complete")

    def document(self, suffix):
        try:
            document = json.loads(self.download(suffix, 16 * 1024 * 1024))
        except (ValueError, UnicodeError) as error:
            raise MetadataError("GitHub returned invalid run data") from error
        if not isinstance(document, dict):
            raise MetadataError("GitHub returned invalid run data")
        return document

    def jobs(self, run_id):
        jobs = []
        for page in range(1, 101):
            batch = self.document(f"runs/{run_id}/jobs?filter=all&per_page=100&page={page}").get("jobs")
            if not isinstance(batch, list) or any(not isinstance(job, dict) for job in batch):
                raise MetadataError("GitHub returned an invalid jobs list")
            jobs.extend(batch)
            if len(batch) < 100:
                return jobs
        raise MetadataError("Workflow jobs exceed the pagination limit")


def validate_record(record):
    if not isinstance(record, dict) or not set(FIELDS).issubset(record):
        raise MetadataError("Incomplete compiled SukiSU identity")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise MetadataError("Unsupported compiled SukiSU identity schema")
    if not isinstance(record["kernel_label"], str) or not LABEL.fullmatch(record["kernel_label"]):
        raise MetadataError("Invalid compiled kernel label")
    for field, length in (("kernel_source_sha", 40), ("expected_certificate_sha256", 64)):
        if not isinstance(record[field], str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", record[field]):
            raise MetadataError("Invalid compiled source or certificate identity")
    for field in ("version_code", "uapi", "expected_certificate_size", "compiled_command_files_count"):
        if type(record[field]) is not int or not 0 < record[field] <= 2_100_000_000:
            raise MetadataError("Invalid compiled identity integer")
    if not 64 <= record["expected_certificate_size"] <= 4096:
        raise MetadataError("Invalid compiled certificate size")
    if not isinstance(record["manager_package_name"], str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", record["manager_package_name"]):
        raise MetadataError("Invalid compiled manager package")
    return {field: record[field] for field in FIELDS}


def records_from_stream(stream):
    records = {}
    while True:
        raw = stream.readline(65537)
        if not raw:
            break
        if len(raw) > 65536:
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(65537)
            continue
        line = raw.decode("utf-8", errors="replace").strip()
        marked = MARKER in line
        payload = line.split(MARKER, 1)[1].strip() if marked else line[line.find("{"):]
        if not payload.startswith("{"):
            continue
        try:
            record = json.loads(payload)
        except ValueError:
            if marked:
                raise MetadataError("Malformed marked SukiSU identity in kernel logs") from None
            continue
        if not marked and (not isinstance(record, dict) or not set(FIELDS).issubset(record)):
            continue
        record = validate_record(record)
        label = record["kernel_label"]
        if label in records and records[label] != record:
            raise MetadataError("Conflicting compiled identities in kernel logs")
        records[label] = record
    return records


def records_from_zip(payload):
    if len(payload) > MAX_DOWNLOAD:
        raise MetadataError("Workflow log archive exceeds the size limit")
    records = {}
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES or sum(item.file_size for item in entries) > MAX_UNCOMPRESSED:
                raise MetadataError("Expanded workflow logs exceed the size limit")
            for entry in entries:
                raw_name = entry.orig_filename
                parts = raw_name.rstrip("/").split("/")
                if (raw_name.startswith("/") or "\\" in raw_name
                        or any(part in {"", ".", ".."} or ":" in part for part in parts)):
                    raise MetadataError("Unsafe path in workflow log archive")
                if entry.is_dir() or not entry.filename.endswith(".txt"):
                    continue
                if entry.file_size > MAX_LOG or entry.flag_bits & 1:
                    raise MetadataError("Kernel log entry exceeds the size limit or is encrypted")
                with archive.open(entry) as stream:
                    found = records_from_stream(stream)
                for label, record in found.items():
                    if label in records and records[label] != record:
                        raise MetadataError("Conflicting compiled identities in workflow logs")
                    records[label] = record
    except MetadataError:
        raise
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise MetadataError("Cannot read the workflow log archive") from error
    return records


def successful_kernel_jobs(jobs, run_id, head_sha):
    selected = {}
    for job in jobs:
        if (job.get("status") != "completed" or job.get("conclusion") != "success"
                or not any(step.get("name") == STEP_NAME and step.get("conclusion") == "success"
                           for step in job.get("steps", []) if isinstance(step, dict))):
            continue
        if (("run_id" in job and job["run_id"] != run_id)
                or ("head_sha" in job and job["head_sha"] != head_sha)):
            raise MetadataError("Kernel job belongs to a different workflow run or source")
        matches = {f'{match["android"]}-{match["kernel"]}-{match["patch"]}'
                   for match in JOB_LABEL.finditer(job.get("name", ""))}
        if len(matches) != 1 or type(job.get("id")) is not int or job["id"] < 1:
            raise MetadataError("Cannot identify the completed kernel job")
        label = matches.pop()
        if label not in selected or job["id"] > selected[label]["id"]:
            selected[label] = job
    if not selected:
        raise MetadataError("No successful kernel jobs with compiled SukiSU identities were found")
    return selected


def read_run_metadata(api, run_id):
    if type(run_id) is not int or run_id < 1:
        raise MetadataError("Invalid workflow run ID")
    run = api.document(f"runs/{run_id}")
    repository = run.get("repository")
    if (run.get("id") != run_id or not isinstance(repository, dict)
            or not isinstance(repository.get("full_name"), str) or repository["full_name"].lower()
            != api.repository.lower() or not re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", ""))):
        raise MetadataError("Workflow run provenance does not match the requested repository")
    identity = {"repository": api.repository.lower(), "run_id": run_id, "head_sha": run["head_sha"]}
    jobs = successful_kernel_jobs(api.jobs(run_id), run_id, run["head_sha"])
    records = {}
    if run.get("status") == "completed":
        try:
            records = records_from_zip(api.download(f"runs/{run_id}/logs"))
        except MetadataError as error:
            if "GitHub log request" not in str(error):
                raise
    missing = sorted(set(jobs) - set(records))
    def read_job(label):
        payload = api.download(f'jobs/{jobs[label]["id"]}/logs', MAX_LOG)
        found = records_from_stream(io.BytesIO(payload))
        if set(found) != {label}:
            raise MetadataError("A successful kernel job has missing or unexpected compiled identity records")
        return label, found[label], len(payload)
    total = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        for label, record, size in executor.map(read_job, missing):
            total += size
            if total > MAX_UNCOMPRESSED:
                raise MetadataError("Downloaded kernel logs exceed the total size limit")
            records[label] = record
    return identity, {label: records[label] for label in sorted(jobs)}


def write_records(output_dir, identity, records):
    output_dir = Path(output_dir)
    stamp = output_dir / ".source-run"
    if output_dir.exists() and output_dir.is_symlink():
        raise MetadataError("Metadata output must not be a symlink")
    if stamp.exists():
        if stamp.is_symlink() or json.loads(stamp.read_text(encoding="utf-8")) != identity:
            raise MetadataError("Cached identities belong to another workflow run or source")
    elif output_dir.exists() and any(output_dir.glob("*.json")):
        raise MetadataError("Cached identities lack workflow run provenance")
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("*.json"):
        if path.is_symlink() or validate_record(json.loads(path.read_text(encoding="utf-8")))["kernel_label"] + ".json" != path.name:
            raise MetadataError("Invalid cached compiled identity")
    for label, record in records.items():
        record = validate_record(record)
        if record["kernel_label"] != label:
            raise MetadataError("Compiled identity label does not match its output name")
        (output_dir / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    stamp.write_text(json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        api = GitHubLogs(args.repository, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", ""))
        identity, records = read_run_metadata(api, args.run_id)
        write_records(args.output_dir, identity, records)
    except (MetadataError, OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, (str(error) if isinstance(error, MetadataError) else "Invalid compiled SukiSU log data") + "\n")
    print(f"Recovered {len(records)} compiled SukiSU identities from workflow run {args.run_id} logs")


if __name__ == "__main__":
    main()
