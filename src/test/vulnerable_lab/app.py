#!/usr/bin/env python3
"""Deliberately vulnerable local lab app for BypassFuzzer."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TRUTHY_VALUES = {"1", "true", "yes", "on", "admin", "root"}
ADMIN_KEYS = {"debug", "is_admin", "isadmin", "access", "role"}
TRUSTED_HOST = "trusted.example"
LOOPBACK_ALIASES = {"127.0.0.1", "127.1", "2130706433", "0x7f000001", "localhost", "::1", "[::1]"}
PATH_NORMALIZATION_ROUTES = {
    "/api/v1/reports/export": "reports export",
    "/tenant/acme/billing/invoices": "billing invoices",
    "/console/settings/users": "console users",
}
HEADER_TRUST_ROUTE = "/edge/private/reports/quarterly"
VERB_ROUTE = "/rest/admin/users/42"
PARAM_ROUTE = "/api/internal/runtime/config"
COOKIE_ROUTE = "/portal/account/export"
TRAILING_DOT_ROUTE = "/edge/admin/console"
CONTENT_TYPE_ROUTE = "/graphql/internal/preferences"
PROTOCOL_ROUTE = "/legacy/admin/audit"
BEARER_ADMIN_ROUTE = "/api/v2/admin/audit"
WEAK_BEARER_ADMIN_VALUES = {"Bearer", "Bearer A", "Bearer a a", "Token A"}
TRUSTED_REWRITE_TARGETS = {HEADER_TRUST_ROUTE, "/internal/reports/export", "/admin/reports/export"}


def parse_cookie_pairs(cookie_header: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not cookie_header:
        return pairs

    for part in cookie_header.split(";"):
        trimmed = part.strip()
        if not trimmed or "=" not in trimmed:
            continue
        name, value = trimmed.split("=", 1)
        pairs.append((name.strip(), value.strip()))
    return pairs


def parse_multipart(body: bytes, content_type: str) -> list[tuple[str, str]]:
    match = re.search(r"boundary=([^;]+)", content_type)
    if not match:
        return []

    boundary = match.group(1).strip().strip('"')
    delimiter = ("--" + boundary).encode()
    parts: list[tuple[str, str]] = []

    for segment in body.split(delimiter):
        if b"Content-Disposition: form-data" not in segment:
            continue

        name_match = re.search(br'name="([^"]+)"', segment)
        if not name_match:
            continue

        body_index = segment.find(b"\r\n\r\n")
        if body_index == -1:
            continue

        value = segment[body_index + 4 :].strip(b"\r\n- ").decode("utf-8", "replace")
        parts.append((name_match.group(1).decode("utf-8", "replace"), value))

    return parts


def parse_body_pairs(body: bytes, content_type: str) -> list[tuple[str, str]]:
    body_text = body.decode("utf-8", "replace")
    if not content_type:
        return []

    if "application/x-www-form-urlencoded" in content_type:
        return urllib.parse.parse_qsl(body_text, keep_blank_values=True)

    if "application/json" in content_type:
        try:
            data = json.loads(body_text)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            return [(str(key), "" if value is None else str(value)) for key, value in data.items()]
        return []

    if "application/xml" in content_type or "text/xml" in content_type:
        try:
            root = ET.fromstring(body_text)
        except ET.ParseError:
            return []
        return [(child.tag, child.text or "") for child in list(root)]

    if "multipart/form-data" in content_type:
        return parse_multipart(body, content_type)

    return []


def has_truthy_admin_pair(pairs: list[tuple[str, str]]) -> bool:
    for name, value in pairs:
        normalized_name = name.lower()
        normalized_value = value.lower()
        if normalized_name in ADMIN_KEYS and normalized_value in TRUTHY_VALUES:
            return True
        if normalized_name == "role" and normalized_value == "administrator":
            return True
    return False


def has_admin_key(pairs: list[tuple[str, str]]) -> bool:
    return any(name.lower() in ADMIN_KEYS for name, _ in pairs)


def normalize_backend_path(raw_path: str) -> str:
    path = urllib.parse.urlsplit(raw_path).path

    for _ in range(2):
        path = urllib.parse.unquote(path)

    path = path.replace(";", "/")
    path = re.sub(r"/{2,}", "/", path)
    path = path.replace("/./", "/")
    path = normalize_dot_segments(path).rstrip("/")
    if path.endswith("."):
        path = path[:-1]
    path = re.sub(r"\.(json|xml|txt|html|php|bak)$", "", path, flags=re.IGNORECASE)

    lowered = path.lower()
    if lowered in {"", "/"}:
        return "/"
    return lowered


def normalize_dot_segments(path: str) -> str:
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def parse_target_host(value: str) -> str:
    if not value:
        return ""

    trimmed = value.strip()
    if not trimmed:
        return ""

    if trimmed.startswith("//"):
        parsed = urllib.parse.urlsplit("http:" + trimmed)
        return (parsed.hostname or "").lower()

    if "://" in trimmed:
        parsed = urllib.parse.urlsplit(trimmed)
        return (parsed.hostname or "").lower()

    host_only = trimmed.split("/", 1)[0]
    if "@" in host_only:
        host_only = host_only.split("@", 1)[1]
    if ":" in host_only and not host_only.startswith("["):
        host_only = host_only.split(":", 1)[0]
    return host_only.strip().lower()


def is_loopback_alias(host: str) -> bool:
    normalized = (host or "").strip().lower()
    return normalized in LOOPBACK_ALIASES


def string_contains_trusted_host(raw_value: str) -> bool:
    return TRUSTED_HOST in (raw_value or "").lower()


class VulnerableLabHandler(BaseHTTPRequestHandler):
    server_version = "BypassFuzzerVulnerableLab/1.0"

    def do_GET(self) -> None:
        self.handle_request()

    def do_POST(self) -> None:
        self.handle_request()

    def do_PUT(self) -> None:
        self.handle_request()

    def do_PATCH(self) -> None:
        self.handle_request()

    def do_DELETE(self) -> None:
        self.handle_request()

    def do_HEAD(self) -> None:
        self.handle_request(send_body=False)

    def do_OPTIONS(self) -> None:
        self.handle_request()

    def log_message(self, format: str, *args: object) -> None:
        return

    def handle_request(self, send_body: bool = True) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        raw_path = parsed.path
        exact_path = urllib.parse.unquote(parsed.path)
        normalized_path = normalize_backend_path(self.path)
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        cookie_pairs = parse_cookie_pairs(self.headers.get("Cookie", ""))
        body_pairs, content_type = self.read_body_pairs()
        authenticated = any(name == "session" and value == "lab-user" for name, value in cookie_pairs)

        if exact_path == "/":
            self.respond(
                HTTPStatus.OK,
                (
                    "BypassFuzzer vulnerable lab\n"
                    "Visit /login first, then try "
                    "/edge/private/reports/quarterly, /api/v1/reports/export, /tenant/acme/billing/invoices, "
                    "/console/settings/users, /rest/admin/users/42, /api/internal/runtime/config, "
                    "/portal/account/export, /edge/admin/console, /graphql/internal/preferences, "
                    "/api/v2/admin/audit, /legacy/admin/audit, /redirect/next, /host/check, and /cors/profile\n"
                ),
                send_body,
            )
            return

        if exact_path == "/login":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Set-Cookie", "session=lab-user; Path=/")
            self.end_headers()
            if send_body:
                self.wfile.write(b"issued session=lab-user\n")
            return

        if exact_path == "/health":
            self.respond(HTTPStatus.OK, "ok\n", send_body)
            return

        if normalized_path in PATH_NORMALIZATION_ROUTES:
            self.handle_path_normalization(
                authenticated,
                raw_path,
                exact_path,
                normalized_path,
                send_body,
            )
            return

        if normalized_path == HEADER_TRUST_ROUTE:
            self.handle_header_trust(authenticated, send_body)
            return

        if normalized_path == VERB_ROUTE:
            self.handle_verb_route(authenticated, send_body)
            return

        if normalized_path == PARAM_ROUTE:
            self.handle_param_route(authenticated, query_pairs, send_body)
            return

        if normalized_path == COOKIE_ROUTE:
            self.handle_cookie_route(authenticated, cookie_pairs, send_body)
            return

        if normalized_path == TRAILING_DOT_ROUTE:
            self.handle_trailing_dot_route(authenticated, send_body)
            return

        if normalized_path == CONTENT_TYPE_ROUTE:
            self.handle_content_type_route(authenticated, exact_path, body_pairs, content_type, send_body)
            return

        if normalized_path == PROTOCOL_ROUTE:
            self.handle_protocol(authenticated, send_body)
            return

        if normalized_path == BEARER_ADMIN_ROUTE:
            self.handle_bearer_admin(raw_path, exact_path, normalized_path, send_body)
            return

        if normalized_path == "/redirect/next":
            self.handle_redirect(authenticated, query_pairs, send_body)
            return

        if normalized_path == "/host/check":
            self.handle_host_validation(authenticated, query_pairs, send_body)
            return

        if normalized_path == "/cors/profile":
            self.handle_cors_profile(authenticated, send_body)
            return

        self.respond(HTTPStatus.NOT_FOUND, "not found\n", send_body)

    def read_body_pairs(self) -> tuple[list[tuple[str, str]], str]:
        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return [], content_type
        body = self.rfile.read(length)
        return parse_body_pairs(body, content_type), content_type

    def handle_path_normalization(
        self,
        authenticated: bool,
        raw_path: str,
        exact_path: str,
        normalized_path: str,
        send_body: bool,
    ) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        resource_name = PATH_NORMALIZATION_ROUTES.get(normalized_path, "resource")
        if raw_path != normalized_path or exact_path != normalized_path:
            self.respond(
                HTTPStatus.OK,
                f"{resource_name} bypass granted via: path normalization bypass\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "path normalization bypass"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, f"{resource_name} blocked\n", send_body)

    def handle_header_trust(self, authenticated: bool, send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        reasons: list[str] = []
        if self.headers.get("X-Forwarded-For") in {"127.0.0.1", "127.0.0.1:80", "::1"}:
            reasons.append("trusted X-Forwarded-For")
        if self.headers.get("X-Custom-IP-Authorization") in {"127.0.0.1", "::1"}:
            reasons.append("trusted X-Custom-IP-Authorization")
        if self.headers.get("X-Forwarded-Host", "").lower() in {"localhost", "internal.local", "localhost:8080"}:
            reasons.append("trusted X-Forwarded-Host")
        if self.headers.get("Host", "").lower() in {"localhost", "internal.local"}:
            reasons.append("trusted Host")

        original_url = self.headers.get("X-Original-URL", "")
        rewrite_url = self.headers.get("X-Rewrite-URL", "")
        if normalize_backend_path(original_url) in TRUSTED_REWRITE_TARGETS:
            reasons.append("trusted X-Original-URL")
        if normalize_backend_path(rewrite_url) in TRUSTED_REWRITE_TARGETS:
            reasons.append("trusted X-Rewrite-URL")

        if reasons:
            self.respond(
                HTTPStatus.OK,
                "edge report bypass granted via: " + ", ".join(reasons) + "\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": ",".join(reasons)},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "edge report blocked\n", send_body)

    def handle_verb_route(self, authenticated: bool, send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        reasons: list[str] = []
        if self.command in {"HEAD", "OPTIONS", "TRACE"}:
            reasons.append("method confusion")

        override_headers = (
            self.headers.get("X-HTTP-Method-Override", ""),
            self.headers.get("X-HTTP-Method", ""),
            self.headers.get("X-Method-Override", ""),
        )
        if any(value.upper() == "GET" for value in override_headers):
            reasons.append("method override header")

        if reasons:
            self.respond(
                HTTPStatus.OK,
                "user-management bypass granted via: " + ", ".join(reasons) + "\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": ",".join(reasons)},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "user-management blocked\n", send_body)

    def handle_param_route(
        self,
        authenticated: bool,
        query_pairs: list[tuple[str, str]],
        send_body: bool,
    ) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        if has_truthy_admin_pair(query_pairs):
            self.respond(
                HTTPStatus.OK,
                "runtime config bypass granted via: truthy query parameter\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "truthy query parameter"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "runtime config blocked\n", send_body)

    def handle_cookie_route(
        self,
        authenticated: bool,
        cookie_pairs: list[tuple[str, str]],
        send_body: bool,
    ) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        if has_truthy_admin_pair(cookie_pairs):
            self.respond(
                HTTPStatus.OK,
                "account export bypass granted via: truthy cookie parameter\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "truthy cookie parameter"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "account export blocked\n", send_body)

    def handle_trailing_dot_route(self, authenticated: bool, send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        if self.headers.get("Host", "").endswith("."):
            self.respond(
                HTTPStatus.OK,
                "edge console bypass granted via: trusted trailing-dot Host\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "trusted trailing-dot Host"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "edge console blocked\n", send_body)

    def handle_content_type_route(
        self,
        authenticated: bool,
        exact_path: str,
        body_pairs: list[tuple[str, str]],
        content_type: str,
        send_body: bool,
    ) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        non_form_content_type = any(token in content_type for token in ("application/json", "application/xml", "text/xml", "multipart/form-data"))
        if exact_path == CONTENT_TYPE_ROUTE and body_pairs and non_form_content_type and has_admin_key(body_pairs):
            self.respond(
                HTTPStatus.OK,
                "graphql preferences bypass granted via: content-type parser confusion\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "content-type parser confusion"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "graphql preferences blocked\n", send_body)

    def handle_protocol(self, authenticated: bool, send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        if self.request_version == "HTTP/1.0":
            self.respond(
                HTTPStatus.OK,
                "protocol bypass granted via HTTP/1.0\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "http-1.0"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, f"protocol blocked for {self.request_version}\n", send_body)

    def handle_bearer_admin(self, raw_path: str, exact_path: str, normalized_path: str, send_body: bool) -> None:
        authorization = self.headers.get("Authorization", "").strip()
        if not authorization:
            self.respond(HTTPStatus.UNAUTHORIZED, "bearer token required\n", send_body)
            return

        reasons: list[str] = []
        if raw_path != normalized_path or exact_path != normalized_path:
            reasons.append("path normalization bypass")
        if authorization in WEAK_BEARER_ADMIN_VALUES:
            reasons.append("weak bearer token validation")

        if reasons:
            self.respond(
                HTTPStatus.OK,
                "audit bypass granted via: " + ", ".join(reasons) + "\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": ",".join(reasons)},
            )
            return

        if authorization == "Bearer admin-token":
            self.respond(HTTPStatus.OK, "audit access granted\n", send_body)
            return

        if authorization.startswith("Bearer "):
            self.respond(HTTPStatus.FORBIDDEN, "bearer token lacks required scope\n", send_body)
            return

        self.respond(HTTPStatus.FORBIDDEN, "invalid bearer token\n", send_body)

    def handle_redirect(self, authenticated: bool, query_pairs: list[tuple[str, str]], send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        next_value = next((value for name, value in query_pairs if name == "next"), "")
        target_host = parse_target_host(next_value)
        bypass = string_contains_trusted_host(next_value) and target_host not in {"", TRUSTED_HOST}

        if bypass:
            self.respond(
                HTTPStatus.OK,
                "redirect bypass granted via URL validation confusion\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "url-allowlist-bypass"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "redirect blocked by URL validation\n", send_body)

    def handle_host_validation(self, authenticated: bool, query_pairs: list[tuple[str, str]], send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        host_value = next((value for name, value in query_pairs if name == "host"), "")
        normalized_host = parse_target_host(host_value)
        bypass = string_contains_trusted_host(host_value) and normalized_host not in {"", TRUSTED_HOST}

        if bypass:
            self.respond(
                HTTPStatus.OK,
                "hostname bypass granted via weak allowlist match\n",
                send_body,
                extra_headers={"X-Smoke-Bypass": "hostname-allowlist-bypass"},
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "hostname blocked by validation\n", send_body)

    def handle_cors_profile(self, authenticated: bool, send_body: bool) -> None:
        if not authenticated:
            self.respond(HTTPStatus.UNAUTHORIZED, "login required\n", send_body)
            return

        origin = self.headers.get("Origin", "")
        origin_host = parse_target_host(origin)
        bypass = string_contains_trusted_host(origin) and origin_host not in {"", TRUSTED_HOST}

        if bypass:
            self.respond(
                HTTPStatus.OK,
                "cors bypass granted via weak origin validation\n",
                send_body,
                extra_headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                    "X-Smoke-Bypass": "cors-origin-bypass",
                },
            )
            return

        self.respond(HTTPStatus.FORBIDDEN, "origin blocked by validation\n", send_body)

    def respond(
        self,
        status: HTTPStatus,
        body: str,
        send_body: bool,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if send_body:
            self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the BypassFuzzer vulnerable lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8008, type=int)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), VulnerableLabHandler)
    print(f"BypassFuzzer vulnerable lab listening on http://{args.host}:{args.port}")
    print("Open /login first to receive session=lab-user")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
