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

This suite starts the lab automatically and drives the real attack classes, payload expansion, registry wiring, and shared executor path without Burp.

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
- `run_smoke_tests.py` is retained as a fast black-box check for the lab itself.
- Several playbooks intentionally converge on the same vulnerable behavior in this lab, especially path normalization around `/admin`.
- The lab uses Python stdlib only, so it is easy to run locally and easy to inspect when a smoke case fails.
