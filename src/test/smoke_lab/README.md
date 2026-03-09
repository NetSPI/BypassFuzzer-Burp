# BypassFuzzer Smoke Lab

This is a deliberately vulnerable local app for smoke-testing the extension against live traffic without setting up a full lab stack.

## Run

```bash
python3 src/test/smoke_lab/app.py
```

Default listener:

- `http://127.0.0.1:8008`

Primary attack-driven smoke suite:

```bash
./gradlew smokeTestPlaybooks
```

This suite starts the lab automatically and drives the real attack classes, payload expansion, registry wiring, shared executor path, and URL Validation playbook without Burp.

Black-box lab self-check:

```bash
python3 src/test/smoke_lab/run_smoke_tests.py
```

Prime the session first:

```http
GET /login HTTP/1.1
Host: 127.0.0.1:8008
```

That issues `session=lab-user`, which keeps the requests authenticated enough for the bypass cases to be meaningful.

## Recommended smoke targets

## Coverage Matrix

| Attack | Representative request | Expected bypass marker |
| --- | --- | --- |
| Header | `GET /admin` with `X-Forwarded-For: 127.0.0.1` | `trusted X-Forwarded-For` |
| Path | `GET /..;/admin` | `path normalization bypass` |
| Verb | `OPTIONS /admin` | `method confusion` |
| Param | `GET /api/admin/settings?debug=true` | `truthy query parameter` |
| Cookie | `GET /api/admin/settings` with `Cookie: session=lab-user; debug=true` | `truthy cookie parameter` |
| Trailing Dot | `GET /admin` with `Host: 127.0.0.1.` | `trusted trailing-dot Host` |
| Trailing Slash | `GET /admin/` | `path normalization bypass` |
| Extension | `GET /admin.json` | `path normalization bypass` |
| Content-Type | `POST /api/admin/settings` with JSON body | `content-type parser confusion` |
| Encoding | `GET /%61dmin` | `path normalization bypass` |
| Protocol | `GET /protocol/admin` over `HTTP/1.0` | `http-1.0` |
| Case | `GET /ADMIN` | `path normalization bypass` |
| URL Validation (Absolute URL) | `GET /redirect/next?next={INJECT}` | `url-allowlist-bypass` |
| URL Validation (Hostname) | `GET /host/check?host={INJECT}` | `hostname-allowlist-bypass` |
| URL Validation (CORS Origin) | `GET /cors/profile` with `Origin: {INJECT}` | `cors-origin-bypass` |

### Header, Path, Case, Trailing Slash, Extension, Encoding

Base request:

```http
GET /admin HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 admin blocked`

Expected bypasses:

- header trust: `X-Forwarded-For`, `X-Custom-IP-Authorization`, `X-Original-URL`, `X-Rewrite-URL`, `Host`, `X-Forwarded-Host`
- path normalization: case flips, encoded path segments, trailing slash, trailing dot, extension suffixes

### Param and Cookie

Base request:

```http
GET /api/admin/settings?debug=false&role=user HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 settings blocked`

Expected bypasses:

- truthy query params such as `debug=true`, `is_admin=1`, `role=admin`
- truthy cookies such as `debug=true`, `role=admin`

### Content-Type and Verb Query-to-Body Moves

Base request:

```http
GET /api/admin/settings?debug=false HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 settings blocked`

Expected bypasses:

- if the request is converted to `POST` with `application/json`, `application/xml`, `text/xml`, or `multipart/form-data` and the body still carries `debug`, `is_admin`, `access`, or `role`, the app returns `200 settings bypass granted via: content-type parser confusion`

That makes it useful for testing the extension's content-type conversion behavior without also needing a value change.

### Protocol

Base request:

```http
GET /protocol/admin HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 protocol blocked for HTTP/1.1`

Expected bypass:

- `HTTP/1.0` returns `200 protocol bypass granted via HTTP/1.0`

### URL Validation

Base requests:

```http
GET /redirect/next?next={INJECT} HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

```http
GET /host/check?host={INJECT} HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

```http
GET /cors/profile HTTP/1.1
Host: 127.0.0.1:8008
Origin: {INJECT}
Cookie: session=lab-user
```

Expected baseline:

- `403` on all three routes

Expected bypasses:

- absolute URL allowlist confusion on `/redirect/next`
- hostname allowlist confusion on `/host/check`
- weak CORS origin allowlist matching on `/cors/profile`

The attack-driven smoke suite uses the real `UrlValidationAttack` with:

- `allowedHost=trusted.example`
- `attackerHost=127.0.0.1`
- explicit `{INJECT}` markers in the request
- raw payload mode for deterministic smoke coverage

The Burp UI for this tab is marker-driven:

- edit the request directly in the `URL Validation` workbench
- place `{INJECT}` where the payload should go
- `Origin: {INJECT}` should usually be paired with the `CORS` payload family
- choose the payload families you want to run: `Absolute URL`, `Host header`, and/or `CORS`
- default family selection is `Absolute URL`
- choose the attack settings you want to include:
  `Domain allow list bypass`, `Fake relative URLs`, `Loopback`, `IPv6`, `Cloud metadata endpoints`, `URL-splitting Unicode characters`
- choose one encoding mode: `Raw`, `Intruder's`, `Everything`, `Special chars`, or `Unicode escape`
- `View Payloads` shows the exact generated list before execution
- results label the generated `Family`, `Encoding`, and final injected `Payload`

Note:

- this lab is built on Python stdlib `http.server`, so it is useful for `HTTP/1.0` vs `HTTP/1.1` smoke checks
- it is not a full HTTP/2 target

## Response markers

Successful bypass responses include:

- status `200`
- header `X-Smoke-Bypass`
- body text naming the bypass reason

Blocked responses are `403`, and unauthenticated requests are `401`.

## Notes

- `smokeTestPlaybooks` is the main smoke suite. It uses the extension's real attack classes and runs until each playbook finds a representative bypass.
- `run_smoke_tests.py` is retained as a fast black-box check for the lab itself, including the URL Validation routes.
- Several playbooks intentionally converge on the same vulnerable behavior in this lab, especially path normalization around `/admin`.
- The lab uses Python stdlib only, so it is easy to run locally and easy to inspect when a smoke case fails.
