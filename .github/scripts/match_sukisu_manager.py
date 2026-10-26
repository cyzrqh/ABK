#!/usr/bin/env python3
"""Match unmodified, officially signed managers to versions actually built in kernels."""

import argparse
import base64
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


OFFICIAL_REPO = "SukiSU-Ultra/SukiSU-Ultra"
SHA = re.compile(r"[0-9a-fA-F]{40}")
CERT = re.compile(r"[0-9a-fA-F]{64}")
RELEASE_TAG = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.-]+)?")
UAPI = re.compile(
    r"(?m)^\s*(?:static\s+const\s+__u32\s+KERNEL_SU_UAPI_VERSION\s*=\s*"
    r"|#\s*define\s+KERNEL_SU_UAPI_VERSION\s+)(\d+)[uU]?\s*;?\s*$"
)


def run_checked(arguments):
    return subprocess.check_output(
        [str(argument) for argument in arguments], text=True, encoding="utf-8",
        stderr=subprocess.PIPE,
    ).strip()


def github_api(path):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ABK-manager-match"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    retries = 0
    while True:
        try:
            response = urlopen(Request("https://api.github.com" + path, headers=headers), timeout=60)
            break
        except HTTPError as error:
            error_headers = error.headers or {}
            limited = (error.code == 429 or (error.code == 403 and
                       (error_headers.get("Retry-After") is not None or
                        error_headers.get("X-RateLimit-Remaining") == "0")))
            # A repository-scoped token can be denied on another repo even
            # though the run records are public. A rate limit instead needs
            # backoff; changing authentication must not bypass its wait.
            if (not limited and "Authorization" in headers
                    and error.code in {401, 403, 404}):
                headers.pop("Authorization")
                continue
            if retries >= 2 or not (limited or error.code in {500, 502, 503, 504}):
                raise
            delay = 2 ** (retries + 1)
            retry_after = error_headers.get("Retry-After")
            try:
                if retry_after is not None:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        delay = max(delay, parsedate_to_datetime(retry_after).timestamp() - time.time())
                elif error_headers.get("X-RateLimit-Remaining") == "0":
                    delay = max(delay, float(error_headers.get("X-RateLimit-Reset", "0")) - time.time())
            except (ValueError, TypeError, OverflowError):
                pass
            # Do not retry ahead of a long server-directed wait or stall the
            # whole manager job for a primary rate-limit reset.
            if not 0 <= delay <= 30:
                raise
            retries += 1
            print(f"Official manager API returned HTTP {error.code}; retrying in {delay:g}s",
                  file=sys.stderr)
            time.sleep(delay)
    with response:
        return json.load(response)


def official_runs(api_get, max_runs=200):
    """Inspect at most max_runs records across both official workflows."""
    if not 1 <= max_runs <= 200:
        raise ValueError("The official manager search limit must be between 1 and 200")
    workflows = ["build-manager.yml", "release.yml"]
    active = set(workflows)
    records = []
    page = 1
    while active and len(records) < max_runs:
        for workflow in workflows:
            if workflow not in active or len(records) >= max_runs:
                continue
            limit = min(100, max_runs - len(records))
            # GitHub's page offset depends on per_page. Keep it constant even
            # when only a few of the last page's records will be inspected.
            # A manager can be built and uploaded successfully before a later
            # publishing job fails or cancels the workflow. Its APK is usable only
            # after the successful manager jobs are checked below.
            parameters = {"status": "completed", "per_page": 100, "page": page}
            # Both main and dev publish officially signed managers. Query them
            # together, then exclude pull requests and unrelated branches below.
            # Official release.yml also runs on version tags. Their head_branch
            # is e.g. v4.2.1-r2, not main; excluding them would miss signed APKs
            # such as 41068. Candidate commits are checked against origin/main.
            query = urlencode(parameters)
            try:
                response = api_get(
                    f"/repos/{OFFICIAL_REPO}/actions/workflows/{workflow}/runs?{query}")
            except HTTPError as error:
                if error.code != 404:
                    raise
                active.remove(workflow)
                continue
            batch = response.get("workflow_runs", [])
            if not isinstance(batch, list):
                raise ValueError("Official workflow API returned an invalid runs list")
            records.extend(dict(record, _workflow_file=workflow) for record in batch[:limit])
            if len(batch) < 100:
                active.remove(workflow)
        page += 1
    selected = []
    seen = set()
    for record in sorted(records, key=lambda item: item.get("created_at", ""), reverse=True):
        source = record.get("head_sha", "")
        branch = record.get("head_branch", "")
        branch_allowed = (branch in {"main", "dev"} or
                          (record["_workflow_file"] == "release.yml"
                           and isinstance(branch, str) and RELEASE_TAG.fullmatch(branch)))
        if (record.get("status") != "completed"
                or record.get("conclusion") not in {"success", "cancelled", "failure"}
                or not branch_allowed
                or record.get("event") in {"pull_request", "pull_request_target"}
                or type(record.get("id")) is not int or record["id"] <= 0
                or not isinstance(source, str) or not SHA.fullmatch(source)
                or record["id"] in seen):
            continue
        owner = (record.get("head_repository") or {}).get("full_name", OFFICIAL_REPO)
        if owner != OFFICIAL_REPO:
            continue
        if (record["conclusion"] != "success"
                and (record["_workflow_file"] != "build-manager.yml"
                     or record.get("event") != "push"
                     or (record.get("head_repository") or {}).get("full_name") != OFFICIAL_REPO)):
            continue
        # Two runs at one SHA can contain different artifacts, and a cancelled
        # run must not hide a successful one at the same source commit.
        seen.add(record["id"])
        selected.append(record)
    return selected


def verify_manager_jobs(candidate, api_get):
    """Accept only the observed successful normal-manager build/upload shape."""
    run_id, source = candidate["id"], candidate["head_sha"].lower()
    jobs = []
    for page in (1, 2):
        parameters = urlencode({"filter": "latest", "per_page": 100, "page": page})
        response = api_get(f"/repos/{OFFICIAL_REPO}/actions/runs/{run_id}/jobs?{parameters}")
        batch = response.get("jobs", [])
        if not isinstance(batch, list) or any(not isinstance(job, dict) for job in batch):
            raise ValueError("Official manager jobs API returned an invalid jobs list")
        jobs.extend(batch)
        if len(batch) < 100:
            break
    else:
        # Do not trust a partial list when the known manager jobs may belong
        # to another attempt outside this bounded latest-attempt query.
        total = response.get("total_count")
        if type(total) is not int or total > len(jobs):
            raise ValueError("Official manager jobs exceed the 200-job verification limit")
    required = {}
    for job in jobs:
        if "run_id" in job and (type(job["run_id"]) is not int or job["run_id"] != run_id):
            raise ValueError("Official manager job belongs to a different run")
        if "head_sha" in job and (not isinstance(job["head_sha"], str)
                                  or job["head_sha"].lower() != source):
            raise ValueError("Official manager job belongs to a different source")
        name = job.get("name", "")
        match = re.fullmatch(r"(build-manager|repack-manager)\s*\(false\)", name) if isinstance(name, str) else None
        if not match:
            continue
        role = match[1]
        if role in required:
            raise ValueError("Official manager jobs contain ambiguous duplicate manager builds")
        if (job.get("status") != "completed" or job.get("conclusion") != "success"
                or type(job.get("id")) is not int or job["id"] <= 0):
            raise ValueError("Non-success official run did not complete its normal manager jobs successfully")
        required[role] = job
    if set(required) != {"build-manager", "repack-manager"}:
        raise ValueError("Non-success official run has no verified normal manager build and repack jobs")
    steps = required["repack-manager"].get("steps", [])
    uploads = [step for step in steps if isinstance(step, dict)
               and step.get("name") == "Upload build artifact"] if isinstance(steps, list) else []
    if (len(uploads) != 1 or uploads[0].get("status") != "completed"
            or uploads[0].get("conclusion") != "success"):
        raise ValueError("Non-success official run did not successfully upload the normal manager artifact")
    return {role: job["id"] for role, job in required.items()}


def load_kernel_metadata(directory):
    records = []
    for path in sorted(Path(directory).rglob("*.json")):
        with path.open(encoding="utf-8") as stream:
            record = json.load(stream)
        if not isinstance(record, dict):
            raise ValueError(f"Kernel metadata is not an object: {path}")
        if record.get("schema_version") != 1:
            raise ValueError(f"Unsupported kernel metadata schema: {path}")
        for key in ("version_code", "uapi", "expected_certificate_size"):
            if type(record.get(key)) is not int or record[key] <= 0:
                raise ValueError(f"Kernel metadata has an invalid {key}: {path}")
        label = record.get("kernel_label")
        if not isinstance(label, str) or not label.strip() or any(ord(c) < 32 for c in label):
            raise ValueError(f"Kernel metadata has an invalid kernel_label: {path}")
        source = record.get("kernel_source_sha", "")
        certificate = record.get("expected_certificate_sha256", "")
        if not isinstance(source, str) or not SHA.fullmatch(source):
            raise ValueError(f"Kernel metadata has an invalid kernel_source_sha: {path}")
        if not isinstance(certificate, str) or not CERT.fullmatch(certificate.replace(":", "")):
            raise ValueError(f"Kernel metadata has an invalid expected certificate: {path}")
        package = record.get("manager_package_name", "")
        if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
            raise ValueError(f"Kernel metadata has an invalid manager_package_name: {path}")
        record = dict(record)
        record["kernel_source_sha"] = source.lower()
        record["expected_certificate_sha256"] = certificate.replace(":", "").lower()
        records.append(record)
    if not records:
        raise ValueError("No compiled kernel metadata JSON files were found")
    groups = {}
    for record in records:
        key = (record["version_code"], record["uapi"])
        group = groups.setdefault(key, [])
        if group and (group[0]["expected_certificate_sha256"] != record["expected_certificate_sha256"]
                      or group[0]["expected_certificate_size"] != record["expected_certificate_size"]):
            raise ValueError(f"Kernels with version/interface {key} expect different manager certificates")
        if group and group[0]["manager_package_name"] != record["manager_package_name"]:
            raise ValueError(f"Kernels with version/interface {key} expect different manager packages")
        group.append(record)
    return groups


def candidate_metadata(source_dir, source_sha, run, require_main_ancestor=False):
    git = ["git", "-C", str(source_dir)]
    try:
        run(git + ["cat-file", "-e", source_sha + "^{commit}"])
    except subprocess.CalledProcessError:
        run(git + ["fetch", "origin", source_sha])
    if require_main_ancestor:
        for branch in ("main", "dev"):
            try:
                run(git + ["merge-base", "--is-ancestor", source_sha,
                           "refs/remotes/origin/" + branch])
                break
            except subprocess.CalledProcessError:
                continue
        else:
            raise ValueError("Release source is outside official main/dev history")
    count = int(run(git + ["rev-list", "--count", source_sha]))
    for relative in ("uapi/supercall.h", "kernel/include/uapi/supercall.h", "kernel/uapi/supercall.h"):
        try:
            header = run(git + ["show", source_sha + ":" + relative])
        except subprocess.CalledProcessError:
            continue
        versions = UAPI.findall(header)
        if len(versions) == 1 and int(versions[0]) > 0:
            return 40000 + count - 2815, int(versions[0])
        # A header present at the real root must not silently fall back to a
        # different, stale version. A legacy symlink can use the next layout.
        if relative == "uapi/supercall.h" or "KERNEL_SU_UAPI_VERSION" in header:
            raise ValueError("Candidate source has an ambiguous or unsupported UAPI")
    raise ValueError("Candidate source has no readable SukiSU UAPI")


def find_android_tool(name):
    override = os.environ.get(name.upper())
    if override:
        return override
    executable = shutil.which(name)
    if executable:
        return executable
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if not os.environ.get(variable):
            continue
        tools = Path(os.environ[variable]) / "build-tools"
        candidates = sorted(tools.glob("*/" + name), reverse=True)
        if candidates:
            return str(candidates[0])
    raise ValueError(f"Android SDK tool {name} was not found")


def inspect_apk(apk, run=run_checked):
    try:
        aapt = find_android_tool("aapt")
    except ValueError:
        aapt = find_android_tool("aapt2")
    badging = run([aapt, "dump", "badging", str(apk)])
    package = re.search(r"(?m)^package: name='([^']+)' versionCode='([0-9]+)'", badging)
    if not package:
        raise ValueError("Cannot read the APK's real package and versionCode")
    verified = run([find_android_tool("apksigner"), "verify", "--print-certs-pem", "--verbose", str(apk)])
    certificates = re.findall(
        r"(?mi)^Signer #[0-9]+ certificate SHA-256 digest:\s*([0-9a-f:]+)\s*$", verified)
    if len(certificates) != 1 or not CERT.fullmatch(certificates[0].replace(":", "")):
        raise ValueError("APK must have one verified official signing certificate")
    certificate_hash = certificates[0].replace(":", "").lower()
    matching_der = []
    # apksigner's successful verify authenticates these certificates. Decode its
    # PEM output to check the same DER byte length that the kernel checks, and
    # identify the signer rather than an optional APK source-stamp certificate.
    for pem in re.findall(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*"
                          r"-----END CERTIFICATE-----", verified):
        der = base64.b64decode(re.sub(r"\s+", "", pem), validate=True)
        if hashlib.sha256(der).hexdigest() == certificate_hash:
            matching_der.append(der)
    if len(matching_der) != 1:
        raise ValueError("Cannot identify one verified signing certificate in apksigner PEM output")
    return {"package_name": package[1], "version_code": int(package[2]),
            "certificate_sha256": certificate_hash, "certificate_size": len(matching_der[0])}


def download_candidate(candidate, destination):
    source_sha = candidate.get("head_sha", "")
    run_id = candidate.get("id")
    workflow = candidate.get("_workflow_file")
    if (not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)
            or type(run_id) is not int or run_id <= 0
            or workflow not in {"build-manager.yml", "release.yml"}):
        raise ValueError("Official manager candidate has an invalid source, run ID or workflow")
    helper = Path(__file__).with_name("download-manager-from-actions.sh")
    # official_runs already selected the completed run. Pass that exact ID
    # instead of spending two more workflow/head_sha API requests per candidate.
    result = subprocess.run(
        ["bash", str(helper), OFFICIAL_REPO, source_sha, str(destination),
         "--run-id", str(run_id), "--workflow", workflow],
        check=True, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")


def write_pairing(directory, version, uapi, records, candidate, apks):
    certificate = records[0]["expected_certificate_sha256"]
    lines = [
        "Official SukiSU manager matched to compiled kernels",
        f"APK versionCode / kernel KSU_VERSION: {version}",
        f"Manager source UAPI / kernel UAPI: {uapi}",
        f"Official manager source: {candidate['head_sha']}",
        f"Official manager source build: https://github.com/{OFFICIAL_REPO}/actions/runs/{candidate['id']}",
        f"Official workflow conclusion: {candidate['conclusion']}",
        f"Verified APK signing certificate SHA-256: {certificate}",
        f"Verified signing certificate DER byte size: {records[0]['expected_certificate_size']}",
        f"Verified APK package expected by the kernels: {records[0]['manager_package_name']}",
        "",
        "This matches the compiled version, interface and expected official signature.",
        "The kernel and manager sources can differ; this is not an exact-source pairing.",
        "APK files are copied without modification or re-signing.",
        "",
        "Matched kernels (label / kernel's SukiSU source):",
    ]
    if candidate.get("_verified_manager_jobs"):
        jobs = candidate["_verified_manager_jobs"]
        lines[9:9] = ["The normal manager build and artifact upload succeeded despite the workflow conclusion.",
                      f"Verified successful build-manager (false) job: {jobs['build-manager']}",
                      f"Verified successful repack-manager (false) job and artifact upload: {jobs['repack-manager']}"]
    lines.extend(f"- {record['kernel_label']} / {record['kernel_source_sha']}" for record in records)
    lines.extend(["", "Unmodified APK SHA-256:"])
    for apk in apks:
        relative = apk.relative_to(directory)
        lines.append(f"- {relative.as_posix()}: {hashlib.sha256(apk.read_bytes()).hexdigest()}")
    (directory / "PAIRING.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def match_managers(source_dir, metadata_dir, output_dir, *, api_get=github_api,
                   downloader=download_candidate, inspector=inspect_apk, run=run_checked,
                   max_runs=200):
    source_dir, output_dir = Path(source_dir), Path(output_dir)
    if run(["git", "-C", str(source_dir), "rev-parse", "--is-shallow-repository"]) != "false":
        raise ValueError("The official SukiSU repository is shallow; manager version counts are unreliable")
    groups = load_kernel_metadata(metadata_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("Manager output directory must be empty to prevent stale APK uploads")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    candidates = official_runs(api_get, max_runs)
    matched = {}
    failures = []
    source_failures = 0
    ranked = []
    source_metadata = {}
    verified_manager_runs = {}
    # The official workflow and Gradle do not always use the same commit count.
    # A published APK is immutable, whereas a later local history count can
    # differ. Use history only to try likely candidates first; the actual APK
    # manifest is the authority for every final version match.
    for index, candidate in enumerate(candidates):
        try:
            require_ancestor = (candidate["_workflow_file"] == "release.yml"
                                and candidate["head_branch"] not in {"main", "dev"})
            source_key = (candidate["head_sha"].lower(), require_ancestor)
            if source_key not in source_metadata:
                source_metadata[source_key] = candidate_metadata(
                    source_dir, source_key[0], run, require_main_ancestor=require_ancestor)
            estimate, uapi = source_metadata[source_key]
            wanted = [version for version, interface in groups if interface == uapi]
            if wanted:
                ranked.append((min(abs(estimate - version) for version in wanted),
                               index, uapi, candidate))
        except (OSError, ValueError, subprocess.SubprocessError):
            source_failures += 1
    with tempfile.TemporaryDirectory(prefix=".sukisu-manager-match-", dir=output_dir.parent) as temporary:
        temporary = Path(temporary)
        staged = temporary / "verified"
        staged.mkdir()
        for _distance, _index, uapi, candidate in sorted(ranked, key=lambda item: item[:2]):
            source_sha = candidate["head_sha"].lower()
            try:
                if not any(key[1] == uapi and key not in matched for key in groups):
                    continue
                download_dir = temporary / ("download-" + source_sha + "-" + str(candidate["id"]))
                download_dir.mkdir()
                downloader(candidate, download_dir)
                apks = sorted(download_dir.rglob("*.apk"))
                if not apks:
                    raise ValueError("Official manager artifact has no APK")
                verified = {}
                for apk in apks:
                    if apk.is_symlink() or not apk.is_file():
                        raise ValueError("Official artifact contains an invalid APK path")
                    identity = inspector(apk)
                    version = identity["version_code"]
                    key = (version, uapi)
                    if key not in groups or key in matched:
                        failures.append(f"{source_sha}: APK version/interface {version}-{uapi} "
                                        "does not match the pending compiled kernels")
                        continue
                    expected_certificate = groups[key][0]["expected_certificate_sha256"]
                    expected_certificate_size = groups[key][0]["expected_certificate_size"]
                    expected_package = groups[key][0]["manager_package_name"]
                    if identity["package_name"] != expected_package:
                        raise ValueError("APK package does not match the package expected by the kernel")
                    if identity["certificate_sha256"].lower() != expected_certificate:
                        raise ValueError("APK signer does not match the certificate expected by the kernel")
                    if identity["certificate_size"] != expected_certificate_size:
                        raise ValueError("APK certificate DER size does not match the size expected by the kernel")
                    verified.setdefault(key, []).append(apk)
                # Only a non-success run containing a fully matching real APK
                # needs this extra API request. Most candidates cost no jobs
                # lookups, and a successful run keeps its existing path.
                if verified and candidate["conclusion"] != "success":
                    run_id = candidate["id"]
                    if run_id not in verified_manager_runs:
                        verified_manager_runs[run_id] = verify_manager_jobs(candidate, api_get)
                    candidate["_verified_manager_jobs"] = verified_manager_runs[run_id]
                for key, verified_apks in verified.items():
                    version, _interface = key
                    destination = staged / f"{version}-{uapi}"
                    destination.mkdir()
                    copied = []
                    for apk in verified_apks:
                        target = destination / apk.relative_to(download_dir)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(apk, target)
                        copied.append(target)
                    write_pairing(destination, version, uapi, groups[key], candidate, copied)
                    matched[key] = {"version_code": version, "uapi": uapi,
                                    "manager_source_sha": source_sha,
                                    "kernels": [record["kernel_label"] for record in groups[key]]}
                if len(matched) == len(groups):
                    break
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                detail = str(error)
                if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                    stderr = error.stderr.decode("utf-8", errors="replace") if isinstance(error.stderr, bytes) else error.stderr
                    detail += ": " + " ".join(stderr.split())[:400]
                failures.append(f"{source_sha}: {type(error).__name__}: {detail}")
        missing = sorted(set(groups) - set(matched))
        if missing:
            labels = ", ".join(f"{version}-{uapi}" for version, uapi in missing)
            # Preserve the relevant downloaded APK failure instead of replacing
            # it with errors from unrelated legacy sources at the end of a scan.
            detail = "; ".join(failures[:5])
            if source_failures:
                detail += f"; {source_failures} unrelated/unreadable source candidates skipped"
            raise ValueError(f"No verified official manager for compiled kernel version/interface {labels}. "
                             f"No mismatched or re-signed APK will be uploaded. {detail}")
        output_dir.mkdir(exist_ok=True)
        for directory in sorted(staged.iterdir()):
            shutil.move(str(directory), str(output_dir / directory.name))
    return [matched[key] for key in sorted(matched)]


def publish_summary(matches):
    versions = "_".join(f"{item['version_code']}-{item['uapi']}" for item in matches)
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
            stream.write(f"SUKISU_MANAGER_VERSIONS={versions}\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("kversion=" + ",".join(str(item["version_code"]) for item in matches) + "\n")
    lines = ["### Official managers matched to compiled kernels", "",
             "| APK/kernel version | Interface | Official manager source | Kernels |",
             "| --- | --- | --- | --- |"]
    for item in matches:
        kernels = ", ".join(item["kernels"]).replace("|", "\\|")
        lines.append(f"| {item['version_code']} | {item['uapi']} | `{item['manager_source_sha']}` | {kernels} |")
    lines.extend(["", "Version, UAPI and official signing certificate are checked. "
                  "The kernel and manager can use different source commits.", ""])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines))
    print("Verified official SukiSU manager versions: " + versions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--metadata-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--max-runs", type=int, default=200)
    arguments = parser.parse_args()
    try:
        matches = match_managers(arguments.source_dir, arguments.metadata_dir,
                                 arguments.output_dir, max_runs=arguments.max_runs)
        publish_summary(matches)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Cannot match an official SukiSU manager: {error}\n")


if __name__ == "__main__":
    main()
