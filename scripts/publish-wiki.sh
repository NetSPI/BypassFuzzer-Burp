#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${REPO_ROOT}/wiki"
DEFAULT_TARGET_DIR="$(cd "${REPO_ROOT}/.." && pwd)/BypassFuzzer-Burp.wiki"
TARGET_DIR="${WIKI_REPO_DIR:-${DEFAULT_TARGET_DIR}}"
WIKI_REMOTE_URL="${WIKI_REMOTE_URL:-https://github.com/intrudir/BypassFuzzer-Burp.wiki.git}"
WIKI_BRANCH="${WIKI_BRANCH:-master}"
COMMIT_MESSAGE="${WIKI_COMMIT_MESSAGE:-Sync wiki from repo wiki/ directory}"
DO_PUSH=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [--push] [target-dir]

Syncs Markdown pages from the repo's wiki/ directory into the checked-out GitHub wiki repo.

Arguments:
  --push       Commit and push changes after syncing
  target-dir   Optional path to the checked-out .wiki.git repo

Environment:
  WIKI_REPO_DIR       Override the target wiki checkout directory
  WIKI_REMOTE_URL     Override the GitHub wiki remote URL
  WIKI_BRANCH         Override the wiki branch (default: master)
  WIKI_COMMIT_MESSAGE Override the commit message used with --push
EOF
}

while (($# > 0)); do
    case "$1" in
        --push)
            DO_PUSH=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

if [[ ! -d "${SOURCE_DIR}" ]]; then
    echo "Source wiki directory not found: ${SOURCE_DIR}" >&2
    exit 1
fi

mkdir -p "$(dirname "${TARGET_DIR}")"

if [[ ! -d "${TARGET_DIR}/.git" ]]; then
    echo "Cloning wiki repo into ${TARGET_DIR}"
    git clone "${WIKI_REMOTE_URL}" "${TARGET_DIR}"
fi

if [[ ! -d "${TARGET_DIR}/.git" ]]; then
    echo "Target is not a git repository: ${TARGET_DIR}" >&2
    exit 1
fi

pushd "${TARGET_DIR}" >/dev/null

git fetch origin "${WIKI_BRANCH}"
git checkout "${WIKI_BRANCH}"
git pull --ff-only origin "${WIKI_BRANCH}"

find "${TARGET_DIR}" -maxdepth 1 -type f -name "*.md" -delete
cp "${SOURCE_DIR}"/*.md "${TARGET_DIR}/"

echo
echo "Wiki sync complete. Current status:"
git status --short

if git diff --quiet && git diff --cached --quiet; then
    echo
    echo "No wiki changes to commit."
    popd >/dev/null
    exit 0
fi

if [[ "${DO_PUSH}" -eq 1 ]]; then
    git add .
    if git diff --cached --quiet; then
        echo
        echo "No staged wiki changes to commit."
        popd >/dev/null
        exit 0
    fi

    git commit -m "${COMMIT_MESSAGE}"
    git push origin "${WIKI_BRANCH}"
    echo
    echo "Wiki pushed successfully."
else
    echo
    echo "Review changes in ${TARGET_DIR}, then run:"
    echo "  git -C ${TARGET_DIR} add ."
    echo "  git -C ${TARGET_DIR} commit -m \"${COMMIT_MESSAGE}\""
    echo "  git -C ${TARGET_DIR} push origin ${WIKI_BRANCH}"
fi

popd >/dev/null
