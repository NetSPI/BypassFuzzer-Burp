#!/usr/bin/env python3
"""Run representative vulnerable-lab checks for every BypassFuzzer attack playbook."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field


APP_PATH = "src/test/vulnerable_lab/app.py"
DEFAULT_HOST = "127.0.0.1"


@dataclass(frozen=True)
class SmokeCase:
    attack: str
    description: str
    method: str
    path: str
    expected_status: int
    expected_body: str | None = None
    expected_header_value: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str | bytes | None = None
    http_version: int = 11


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_HOST, 0))
        return sock.getsockname()[1]


def wait_until_ready(base_url: str, timeout_seconds: float = 5.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, _, _ = request(base_url, "GET", "/health")
            if status == 200:
                return
        except Exception as exc:  # pragma: no cover - startup race
            last_error = exc
            time.sleep(0.1)
    raise RuntimeError(f"Vulnerable lab did not become ready at {base_url}") from last_error


@contextlib.contextmanager
def running_lab(base_url: str | None):
    if base_url:
        yield base_url
        return

    port = find_free_port()
    url = f"http://{DEFAULT_HOST}:{port}"
    process = subprocess.Popen(
        [sys.executable, APP_PATH, "--host", DEFAULT_HOST, "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_until_ready(url)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def request(
    base_url: str,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    http_version: int = 11,
) -> tuple[int, dict[str, str], str]:
    parsed = urllib.parse.urlsplit(base_url)
    host = parsed.hostname or DEFAULT_HOST
    port = parsed.port or 80
    connection = http.client.HTTPConnection(host, port, timeout=5)
    connection._http_vsn = http_version
    connection._http_vsn_str = f"HTTP/{http_version // 10}.{http_version % 10}"

    header_items = dict(headers or {})
    if body is None:
        payload = None
    elif isinstance(body, bytes):
        payload = body
    else:
        payload = body.encode("utf-8")

    connection.putrequest(method, path, skip_host=True)
    connection.putheader("Host", header_items.pop("Host", f"{host}:{port}"))
    for name, value in header_items.items():
        connection.putheader(name, value)
    if payload is not None and "Content-Length" not in header_items:
        connection.putheader("Content-Length", str(len(payload)))
    connection.endheaders(payload)

    response = connection.getresponse()
    response_headers = {name: value for name, value in response.getheaders()}
    response_body = response.read().decode("utf-8", "replace")
    status = response.status
    connection.close()
    return status, response_headers, response_body


def build_cases() -> list[SmokeCase]:
    auth_cookie = {"Cookie": "session=lab-user"}
    return [
        SmokeCase("Baseline", "Unauthenticated reports export request is rejected", "GET", "/api/v1/reports/export", 401, expected_body="login required"),
        SmokeCase("Baseline", "Authenticated reports export baseline stays blocked", "GET", "/api/v1/reports/export", 403, expected_body="reports export blocked", headers=auth_cookie),
        SmokeCase(
            "Header",
            "Reverse-proxy header trust bypass",
            "GET",
            "/edge/private/reports/quarterly",
            200,
            expected_header_value="trusted X-Forwarded-For",
            headers={**auth_cookie, "X-Forwarded-For": "127.0.0.1"},
        ),
        SmokeCase(
            "Path",
            "Traversal-style payload normalizes back to reports export",
            "GET",
            "/api/v1/../v1/reports/export",
            200,
            expected_header_value="path normalization bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Verb",
            "Method confusion via OPTIONS on a user-management route",
            "OPTIONS",
            "/rest/admin/users/42",
            200,
            expected_header_value="method confusion",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Param",
            "Truthy query parameter bypass on runtime config",
            "GET",
            "/api/internal/runtime/config?debug=true",
            200,
            expected_header_value="truthy query parameter",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Cookie",
            "Truthy cookie parameter bypass on account export",
            "GET",
            "/portal/account/export",
            200,
            expected_header_value="truthy cookie parameter",
            headers={"Cookie": "session=lab-user; debug=true"},
        ),
        SmokeCase(
            "Trailing Dot",
            "Trailing-dot Host bypass on an edge console route",
            "GET",
            "/edge/admin/console",
            200,
            expected_header_value="trusted trailing-dot Host",
            headers={"Host": "127.0.0.1.", "Cookie": "session=lab-user"},
        ),
        SmokeCase(
            "Trailing Slash",
            "Trailing slash path normalization bypass",
            "GET",
            "/api/v1/reports/export/",
            200,
            expected_header_value="path normalization bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Extension",
            "Extension suffix normalization bypass",
            "GET",
            "/api/v1/reports/export.json",
            200,
            expected_header_value="path normalization bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Content-Type",
            "JSON body parser confusion bypass on GraphQL preferences",
            "POST",
            "/graphql/internal/preferences",
            200,
            expected_header_value="content-type parser confusion",
            headers={**auth_cookie, "Content-Type": "application/json"},
            body='{"debug":"false"}',
        ),
        SmokeCase(
            "Encoding",
            "Encoded path bypass",
            "GET",
            "/api/v1/reports/%65xport",
            200,
            expected_header_value="path normalization bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "Protocol",
            "HTTP/1.0 protocol downgrade bypass on a legacy admin route",
            "GET",
            "/legacy/admin/audit",
            200,
            expected_header_value="http-1.0",
            headers=auth_cookie,
            http_version=10,
        ),
        SmokeCase(
            "Bearer",
            "Weak bearer token validation bypass on audit route",
            "GET",
            "/api/v2/admin/audit",
            200,
            expected_header_value="weak bearer token validation",
            headers={"Authorization": "Bearer"},
        ),
        SmokeCase(
            "Case",
            "Case-variant path bypass",
            "GET",
            "/API/V1/REPORTS/EXPORT",
            200,
            expected_header_value="path normalization bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "URL Validation",
            "Absolute URL allowlist confusion bypass",
            "GET",
            "/redirect/next?next=http://trusted.example@127.0.0.1/profile",
            200,
            expected_header_value="url-allowlist-bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "URL Validation",
            "Hostname allowlist confusion bypass",
            "GET",
            "/host/check?host=127.0.0.1.trusted.example",
            200,
            expected_header_value="hostname-allowlist-bypass",
            headers=auth_cookie,
        ),
        SmokeCase(
            "URL Validation",
            "CORS origin allowlist confusion bypass",
            "GET",
            "/cors/profile",
            200,
            expected_header_value="cors-origin-bypass",
            headers={**auth_cookie, "Origin": "http://127.0.0.1.trusted.example"},
        ),
    ]


def run_case(base_url: str, case: SmokeCase) -> tuple[bool, str]:
    status, headers, body = request(
        base_url,
        case.method,
        case.path,
        headers=case.headers,
        body=case.body,
        http_version=case.http_version,
    )
    failures: list[str] = []
    if status != case.expected_status:
        failures.append(f"status={status} expected={case.expected_status}")
    if case.expected_body and case.expected_body not in body:
        failures.append(f"body missing {case.expected_body!r}")
    if case.expected_header_value:
        smoke_header = headers.get("X-Smoke-Bypass", "")
        if case.expected_header_value not in smoke_header:
            failures.append(f"X-Smoke-Bypass={smoke_header!r} missing {case.expected_header_value!r}")

    if failures:
        return False, f"[FAIL] {case.attack}: {case.description} :: " + "; ".join(failures)
    return True, f"[PASS] {case.attack}: {case.description}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run smoke tests for all BypassFuzzer attack playbooks.")
    parser.add_argument("--base-url", help="Use an already running vulnerable lab instead of starting one")
    args = parser.parse_args()

    with running_lab(args.base_url) as base_url:
        failures = 0
        print(f"Running smoke tests against {base_url}")
        for case in build_cases():
            passed, line = run_case(base_url, case)
            print(line)
            if not passed:
                failures += 1

    if failures:
        print(f"{failures} smoke test(s) failed")
        return 1

    print("All smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
