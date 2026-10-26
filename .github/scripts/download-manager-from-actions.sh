#!/usr/bin/env bash
set -euo pipefail

REPO="${1:?repo owner/name required}"
KSU_SHA="${2:?commit SHA required}"
VARIANT_DIR="${3:?output dir required}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
KNOWN_RUN=0

# The matcher has already read these official completed workflow records.
# Keep the historical three-argument SHA lookup for other callers/variants.
if [ "$#" -ne 3 ]; then
  if [ "$#" -ne 7 ] || [ "$4" != "--run-id" ] || [ "$6" != "--workflow" ]; then
    echo "::error::Expected repo SHA output-dir [--run-id ID --workflow FILE]" >&2
    exit 1
  fi
  if [ "$REPO" != "SukiSU-Ultra/SukiSU-Ultra" ] || ! [[ "$KSU_SHA" =~ ^[A-Fa-f0-9]{40}$ ]] \
    || ! [[ "$5" =~ ^[1-9][0-9]*$ ]] \
    || { [ "$7" != "build-manager.yml" ] && [ "$7" != "release.yml" ]; }; then
    echo "::error::Known manager run requires the official SukiSU repo, SHA, positive run ID and workflow" >&2
    exit 1
  fi
  KNOWN_RUN=1
  run_id="$5"
  MANAGER_RUN_SOURCE="${7%.yml}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=resolve-ksu-ref.sh
source "${SCRIPT_DIR}/resolve-ksu-ref.sh"

# Artifact zip names on nightly.link match actions/upload-artifact names + ".zip".
manager_artifact_names() {
  case "$REPO" in
    Baka-SU/BakaSU) printf '%s\n' "Manager-release" ;;
    SukiSU-Ultra/SukiSU-Ultra) printf '%s\n' "Manager" "manager" ;;
    tiann/KernelSU) printf '%s\n' "manager" ;;
    *)
      echo "::error::Unknown repo for nightly.link manager download: ${REPO}" >&2
      exit 1
      ;;
  esac
}

extract_apk_from_zip() {
  local tmp_zip="$1"
  unzip -o "$tmp_zip" -d "$VARIANT_DIR"
  rm -f "$tmp_zip"
  if ! find "$VARIANT_DIR" -type f -name '*.apk' -print -quit | grep -q .; then
    echo "::error::Downloaded artifact did not contain an APK in ${VARIANT_DIR}" >&2
    find "$VARIANT_DIR" -type f | head -20 >&2 || true
    return 1
  fi
}

try_download_artifact_api() {
  local run_id="$1"
  local artifact_names tmp_zip artifact_id artifacts_json

  if [ -z "${GITHUB_TOKEN:-}" ]; then
    return 1
  fi

  artifact_names="$(manager_artifact_names | jq -R . | jq -s .)"
  KSU_API_REPO="$REPO"
  artifacts_json="$(ksu_github_api_curl \
    "https://api.github.com/repos/${REPO}/actions/runs/${run_id}/artifacts")"
  artifact_id="$(printf '%s' "$artifacts_json" | jq -r --argjson names "$artifact_names" '
    [.artifacts[] | select(.expired != true) as $artifact |
      ($names | index($artifact.name)) as $priority |
      select($priority != null) | {id: $artifact.id, priority: $priority}]
    | sort_by(.priority) | .[0].id // empty')"
  if [ -z "$artifact_id" ] || [ "$artifact_id" = "null" ]; then
    echo "::warning::No manager artifact on run ${run_id} for ${REPO}" >&2
    return 1
  fi

  mkdir -p "$VARIANT_DIR"
  tmp_zip="$(mktemp "${TMPDIR:-/tmp}/manager-XXXXXX.zip")"
  if ! ksu_github_api_curl -L \
    "https://api.github.com/repos/${REPO}/actions/artifacts/${artifact_id}/zip" \
    -o "$tmp_zip"; then
    rm -f "$tmp_zip"
    return 1
  fi
  extract_apk_from_zip "$tmp_zip"
  echo "Downloaded manager from ${REPO}@${KSU_SHA} (run ${run_id}, source ${MANAGER_RUN_SOURCE}) via Actions API"
}

try_download_nightly_run() {
  local run_id="$1"
  local artifact_name zip_name url tmp_zip
  while IFS= read -r artifact_name; do
    zip_name="${artifact_name}.zip"
    url="https://nightly.link/${REPO}/actions/runs/${run_id}/${zip_name}"
    mkdir -p "$VARIANT_DIR"
    tmp_zip="$(mktemp "${TMPDIR:-/tmp}/manager-XXXXXX.zip")"

    echo "Downloading manager via nightly.link (run ${run_id}, sha ${KSU_SHA}, source ${MANAGER_RUN_SOURCE}): ${url}"
    # curl retries transient HTTP 429/5xx responses, but never a missing 404
    # artifact. Both normal artifact names always refer to this same run.
    if ! curl -fsSL --retry 2 --retry-delay 2 --retry-max-time 30 -o "$tmp_zip" "$url"; then
      rm -f "$tmp_zip"
      continue
    fi
    extract_apk_from_zip "$tmp_zip" || return 1
    echo "Downloaded manager from ${REPO}@${KSU_SHA} (run ${run_id}, source ${MANAGER_RUN_SOURCE}) via nightly.link"
    return 0
  done < <(manager_artifact_names)
  return 1
}

if [ "$KNOWN_RUN" = "0" ]; then
  if ! ksu_find_manager_run_id "$REPO" "$KSU_SHA"; then
    exit 1
  fi
  run_id="${KSU_MANAGER_RUN_ID}"
fi
if [ "${MANAGER_RUN_FALLBACK_MAIN:-0}" = "1" ]; then
  echo "::notice::Manager APK from latest successful build-manager on main (KSU ref was ${KSU_SHA})" >&2
fi
echo "Manager workflow run for ${REPO}@${KSU_SHA} (source=${MANAGER_RUN_SOURCE}): https://github.com/${REPO}/actions/runs/${run_id}"

# A fork's token cannot download the official repo's Actions artifacts. In the
# known-run path, use nightly.link directly and do not rediscover this same run.
if [ "$KNOWN_RUN" = "1" ] && [ "$REPO" != "$GITHUB_REPOSITORY" ]; then
  if try_download_nightly_run "$run_id"; then
    exit 0
  fi
  echo "::error::Failed to download official manager for ${KSU_SHA} from known run ${run_id} via nightly.link" >&2
  exit 1
fi

if [ -n "${GITHUB_REPOSITORY:-}" ] && [ "$REPO" = "$GITHUB_REPOSITORY" ]; then
  if try_download_artifact_api "$run_id"; then
    exit 0
  fi
  echo "::warning::Actions artifact API failed; trying nightly.link for the same run..." >&2
else
  if try_download_artifact_api "$run_id"; then
    exit 0
  fi
  echo "Fork/cross-repo: Actions artifact zip not available; trying nightly.link for the same run..." >&2
fi

if try_download_nightly_run "$run_id"; then
  exit 0
fi

echo "::error::Failed to download manager for ${REPO}@${KSU_SHA} (run ${run_id}, source ${MANAGER_RUN_SOURCE}) via API and nightly.link" >&2
exit 1
