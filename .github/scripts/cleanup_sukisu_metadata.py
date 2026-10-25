#!/usr/bin/env python3
"""Remove only internal SukiSU metadata artifacts from one workflow run."""

import argparse
import json
import os
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


METADATA_NAME = re.compile(
    r"SukiSU-Metadata-android1[2-6]-(?:5\.10|5\.15|6\.1|6\.6|6\.12)-(?:[0-9]+|X)"
)
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]+")


class CleanupError(RuntimeError):
    pass


def positive_integer(value, description):
    if type(value) is not int or value < 1:
        raise CleanupError(f"Invalid {description}")
    return value


class GitHubAPI:
    def __init__(self, repository, token="", *, opener=urlopen, sleep=time.sleep):
        if (not REPOSITORY.fullmatch(repository)
                or repository.rsplit("/", 1)[1] in {".", ".."}):
            raise CleanupError("Invalid repository")
        self.repository = repository
        self.token = token
        self.opener = opener
        self.sleep = sleep

    def request(self, method, suffix):
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "ABK-metadata-cleanup",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        url = f"https://api.github.com/repos/{self.repository}/actions/{suffix}"
        for attempt in range(4):
            try:
                with self.opener(Request(url, headers=headers, method=method), timeout=30) as response:
                    if method == "DELETE":
                        return True
                    try:
                        document = json.load(response)
                    except (ValueError, UnicodeError) as error:
                        raise CleanupError("GitHub returned invalid artifact data") from error
                    if not isinstance(document, dict):
                        raise CleanupError("GitHub returned invalid artifact data")
                    return document
            except HTTPError as error:
                if method == "DELETE" and error.code == 404:
                    return False
                retry_after = error.headers.get("Retry-After") if error.headers else None
                limited = (error.code == 403 and error.headers
                           and (error.headers.get("X-RateLimit-Remaining") == "0" or retry_after))
                retryable = error.code == 429 or 500 <= error.code <= 599 or limited
                if not retryable or attempt == 3:
                    # Never echo HTTP bodies, request headers, or credentials.
                    raise CleanupError(f"GitHub {method} failed (HTTP {error.code})") from None
                delay = min(10, max(1, int(retry_after))) if retry_after and retry_after.isdigit() else 2 ** attempt
            except (URLError, TimeoutError, ConnectionError):
                if attempt == 3:
                    raise CleanupError(f"GitHub {method} failed after connection retries") from None
                delay = 2 ** attempt
            self.sleep(delay)
        raise CleanupError("GitHub request did not complete")

    def list_artifacts(self, run_id):
        positive_integer(run_id, "workflow run ID")
        artifacts = []
        for page in range(1, 101):
            document = self.request("GET", f"runs/{run_id}/artifacts?per_page=100&page={page}")
            batch = document.get("artifacts")
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise CleanupError("GitHub returned an invalid artifact list")
            artifacts.extend(batch)
            if len(batch) < 100:
                return artifacts
        raise CleanupError("Artifact pagination exceeded the safety limit; no artifacts deleted")

    def delete_artifact(self, artifact_id):
        positive_integer(artifact_id, "artifact ID")
        return self.request("DELETE", f"artifacts/{artifact_id}")


def select_metadata_artifacts(artifacts, run_id):
    positive_integer(run_id, "workflow run ID")
    selected = {}
    for artifact in artifacts:
        name = artifact.get("name")
        if not isinstance(name, str) or not METADATA_NAME.fullmatch(name):
            continue
        artifact_id = positive_integer(artifact.get("id"), "metadata artifact ID")
        provenance = artifact.get("workflow_run")
        # The listing endpoint is already scoped to this run. Some GitHub API
        # responses omit workflow_run entirely; when present it must agree.
        if provenance is not None:
            if (not isinstance(provenance, dict)
                    or type(provenance.get("id")) is not int
                    or provenance["id"] != run_id):
                raise CleanupError("Metadata artifact belongs to a different or unknown workflow run")
        if artifact_id in selected and selected[artifact_id]["name"] != name:
            raise CleanupError("Conflicting metadata artifact identities")
        selected[artifact_id] = {"id": artifact_id, "name": name}
    return list(selected.values())


def cleanup_metadata(api, run_id, *, apply=False):
    # Build the entire validated plan before deleting anything: deletions must
    # not shift pagination, and a bad record must never cause partial cleanup.
    selected = select_metadata_artifacts(api.list_artifacts(run_id), run_id)
    deleted = 0
    missing = 0
    if apply:
        for artifact in selected:
            if api.delete_artifact(artifact["id"]):
                deleted += 1
            else:
                missing += 1
    return {"run_id": run_id, "mode": "apply" if apply else "preview",
            "selected": selected, "deleted": deleted, "already_missing": missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--apply", action="store_true", help="Delete the selected internal records")
    args = parser.parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    try:
        if args.apply and not token:
            raise CleanupError("GH_TOKEN or GITHUB_TOKEN is required to delete artifacts")
        result = cleanup_metadata(GitHubAPI(args.repository, token), args.run_id, apply=args.apply)
    except (CleanupError, OSError) as error:
        message = str(error) if isinstance(error, CleanupError) else "Metadata cleanup failed"
        parser.exit(1, message + "\n")
    if not args.apply:
        for artifact in result["selected"]:
            print(f'{artifact["id"]}: {artifact["name"]}')
    print(f'Internal SukiSU metadata cleanup ({result["mode"]}): '
          f'{len(result["selected"])} selected, {result["deleted"]} deleted, '
          f'{result["already_missing"]} already absent')
    return 0


if __name__ == "__main__":
    sys.exit(main())
