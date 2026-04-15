#!/usr/bin/env python3
"""Sync the bundled URL-validation source data from PortSwigger's upstream repo.

Fetches https://github.com/PortSwigger/url-cheatsheet-data, reads the 6 source
JSON files, and rewrites src/main/resources/payloads/url_validation_source_data.json
in the shape UrlValidationPayloadGenerator expects.

Exits 0 with no changes if already in sync, 0 with changes if the file was
rewritten. Intended to be run from the repo root either manually or by a CI
workflow that opens a pull request on diff.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_URL = "https://github.com/PortSwigger/url-cheatsheet-data.git"
TARGET_FILE = Path("src/main/resources/payloads/url_validation_source_data.json")

# Upstream filename -> (our setting enum name, display name)
CATEGORY_MAP = {
    "domain_allow_list_bypass":         ("DOMAIN_ALLOW_LIST_BYPASS",         "Domain allow list bypass"),
    "fake_relative_urls":                ("FAKE_RELATIVE_URLS",                "Fake relative URLs"),
    "loopback":                          ("LOOPBACK",                          "Loopback"),
    "ipv6":                              ("IPV6",                              "IPv6"),
    "cloud_metadata_endpoints":          ("CLOUD_METADATA_ENDPOINTS",          "Cloud metadata endpoints"),
    # Note: upstream filename has a typo ("spliting") — we keep it on input.
    "url-spliting_unicode_characters":   ("URL_SPLITTING_UNICODE_CHARACTERS",  "URL-splitting Unicode characters"),
}

# Field order in our bundled JSON so diffs stay stable across syncs.
PAYLOAD_FIELD_ORDER = ("payload", "prefix", "suffix", "port", "description", "filters", "tags", "id")


def clone_upstream(dst: Path) -> None:
    subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", REPO_URL, str(dst)],
        check=True,
    )


def canonical_payload(entry: dict) -> dict:
    """Re-order keys and drop keys we don't emit so output is deterministic."""
    out: dict = {}
    for key in PAYLOAD_FIELD_ORDER:
        if key in entry:
            out[key] = entry[key]
    return out


def build_wordlists(upstream_src: Path) -> list[dict]:
    wordlists: list[dict] = []
    for upstream_name, (setting, display) in CATEGORY_MAP.items():
        src = upstream_src / f"{upstream_name}.json"
        if not src.is_file():
            sys.exit(f"Missing upstream source file: {src}")
        with src.open() as fh:
            data = json.load(fh)
        if "payloads" not in data:
            sys.exit(f"Unexpected shape in {src} — no 'payloads' key")
        wordlists.append({
            "setting": setting,
            "name": display,
            "payloads": [canonical_payload(p) for p in data["payloads"]],
        })
    return wordlists


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    target = repo_root / TARGET_FILE
    if not target.is_file():
        sys.exit(f"Target file does not exist: {target}")

    with tempfile.TemporaryDirectory(prefix="url-cheatsheet-sync-") as tmp:
        upstream = Path(tmp) / "url-cheatsheet-data"
        clone_upstream(upstream)
        wordlists = build_wordlists(upstream / "src")

    # Upstream includes at least one payload with a lone high surrogate
    # (U+D83C) to probe URL parsers. Emit raw UTF-8 for valid code points and
    # fall back to \uXXXX escape for the lone surrogates — matches how the
    # existing bundled file is encoded.
    new_bytes = (json.dumps(wordlists, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8", errors="backslashreplace"
    )
    old_bytes = target.read_bytes()

    if new_bytes == old_bytes:
        print("url_validation_source_data.json: already in sync with upstream.")
        return 0

    target.write_bytes(new_bytes)
    total = sum(len(w["payloads"]) for w in wordlists)
    print(f"url_validation_source_data.json: rewrote ({total} payloads across {len(wordlists)} categories).")
    for wordlist in wordlists:
        print(f"  {wordlist['setting']:<36} {len(wordlist['payloads']):>4} payloads")
    print("\nNext steps:")
    print("  1. Review the diff.")
    print("  2. If the rendered cache (url_validation_cheatsheet.json) also needs")
    print("     regenerating for the newly-added payloads, do that in a follow-up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
