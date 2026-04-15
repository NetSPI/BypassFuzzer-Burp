# BypassFuzzer Vulnerable Lab

This is a deliberately vulnerable local app with more realistic endpoint shapes for exercising the extension against live traffic without setting up a full lab stack.

## Run

```bash
python3 src/test/vulnerable_lab/app.py
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
python3 src/test/vulnerable_lab/run_smoke_tests.py
```

Prime the session first:

```http
GET /login HTTP/1.1
Host: 127.0.0.1:8008
```

That issues `session=lab-user`, which keeps the requests authenticated enough for the bypass cases to be meaningful.

## Recommended smoke targets

The lab is meant to double as a consultant demo environment. Each bypass-tab playbook has a named route with a plausible backend mistake behind it instead of everything collapsing onto `/admin`.

## Coverage Matrix

| Attack | Representative request | Expected bypass marker |
| --- | --- | --- |
| Header | `GET /edge/private/reports/quarterly` with `X-Forwarded-For: 127.0.0.1` | `trusted X-Forwarded-For` |
| Path | `GET /api/v1/../v1/reports/export` | `path normalization bypass` |
| Verb | `OPTIONS /rest/admin/users/42` | `method confusion` |
| Param | `GET /api/internal/runtime/config?debug=true` | `truthy query parameter` |
| Cookie | `GET /portal/account/export` with `Cookie: session=lab-user; debug=true` | `truthy cookie parameter` |
| Trailing Dot | `GET /edge/admin/console` with `Host: 127.0.0.1.` | `trusted trailing-dot Host` |
| Trailing Slash | `GET /api/v1/reports/export/` | `path normalization bypass` |
| Extension | `GET /api/v1/reports/export.json` | `path normalization bypass` |
| Content-Type | `POST /graphql/internal/preferences` with JSON body | `content-type parser confusion` |
| Encoding | `GET /api/v1/reports/%65xport` | `path normalization bypass` |
| Protocol | `GET /legacy/admin/audit` over `HTTP/1.0` | `http-1.0` |
| Bearer Demo | `GET /api/v2/admin/audit` with `Authorization: Bearer` | `weak bearer token validation` |
| Case | `GET /API/V1/REPORTS/EXPORT` | `path normalization bypass` |
| URL Validation (Absolute URL) | `GET /redirect/next?next={INJECT}` | `url-allowlist-bypass` |
| URL Validation (Hostname) | `GET /host/check?host={INJECT}` | `hostname-allowlist-bypass` |
| URL Validation (CORS Origin) | `GET /cors/profile` with `Origin: {INJECT}` | `cors-origin-bypass` |
| Realistic: Sacrificial-Prefix | `GET /static/../admin/api/users` | `sacrificial-prefix-exemption` |
| Realistic: Per-Char Encoding | `GET /api/profile/%61lice` | `per-char-encoding` |
| Realistic: Matrix-Suffix | `GET /api/tenants/acme/invoices/INV-42;jsessionid=x` | `matrix-param-suffix` |
| Realistic: Double-Encoding | `GET /api/gateway/%2561dmin` | `double-encoding` |
| Realistic: Splitter | `GET /api/a%09udit/export` | `splitter-via-stripped-chars` |

### Header Trust

Base request:

```http
GET /edge/private/reports/quarterly HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 edge report blocked`

Expected bypasses:

- trusted reverse-proxy headers such as `X-Forwarded-For`, `X-Custom-IP-Authorization`, `X-Forwarded-Host`
- trusted rewrite headers such as `X-Original-URL` and `X-Rewrite-URL`
- useful for demos where an edge route is locked down but the upstream service trusts proxy metadata too much

### Path, Case, Trailing Slash, Extension, Encoding

Base request:

```http
GET /api/v1/reports/export HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 reports export blocked`

Expected bypasses:

- path normalization: case flips, encoded path segments, traversal-like normalizations, trailing slash, extension suffixes
- the same vulnerable path logic is also exposed on `/tenant/acme/billing/invoices` and `/console/settings/users`

Bearer-token example:

```http
GET /api/v2/admin/audit HTTP/1.1
Host: 127.0.0.1:8008
Authorization: Bearer user-token
```

Expected baseline:

- `403 bearer token lacks required scope`

Expected bypass:

- weak bearer-token validation when the `Authorization` header is replaced with values like `Bearer`, `Bearer A`, or `Bearer a a`

### Verb

Base request:

```http
GET /rest/admin/users/42 HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 user-management blocked`

Expected bypasses:

- `OPTIONS`, `HEAD`, or `TRACE` return `200` because the route is protected by a naïve method allowlist
- method override headers such as `X-HTTP-Method-Override: GET` also bypass

### Param

Base request:

```http
GET /api/internal/runtime/config?debug=false&role=user HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 runtime config blocked`

Expected bypasses:

- truthy query params such as `debug=true`, `is_admin=1`, `role=admin`

### Cookie

Base request:

```http
GET /portal/account/export HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user; debug=false
```

Expected baseline:

- `403 account export blocked`

Expected bypasses:

- truthy cookies such as `debug=true`, `role=admin`

### Content-Type

Base request:

```http
GET /graphql/internal/preferences?debug=false HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 graphql preferences blocked`

Expected bypasses:

- if the request is converted to `POST` with `application/json`, `application/xml`, `text/xml`, or `multipart/form-data` and the body still carries `debug`, `is_admin`, `access`, or `role`, the app returns `200 graphql preferences bypass granted via: content-type parser confusion`

That makes it useful for testing the extension's content-type conversion behavior without also needing a value change.

### Trailing Dot

Base request:

```http
GET /edge/admin/console HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

Expected baseline:

- `403 edge console blocked`

Expected bypass:

- `Host: 127.0.0.1.` returns `200 edge console bypass granted via: trusted trailing-dot Host`

### Protocol

Base request:

```http
GET /legacy/admin/audit HTTP/1.1
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

## Realistic Bypass Routes

Five routes model specific WAF+origin disagreement bugs you'd find in production. Each baseline returns `403` with a realistic error JSON. Each bypass returns `200` with plausible sensitive data and an `X-Smoke-Bypass` header naming the technique. The handlers are implemented as two explicit layers (WAF check, then origin dispatch) so the bug shape is readable directly from the source.

### `/admin/api/users` — sacrificial-prefix exemption

**Bug modeled:** AuthZ middleware exempts asset-serving prefixes (`/static/*`, `/public/*`, `/assets/*`, `/images/*`) from the auth check. The exemption test runs on the RAW path; dispatch runs on the NORMALIZED path.

```http
GET /admin/api/users HTTP/1.1                   # baseline -> 403 admin role required
GET /static/../admin/api/users HTTP/1.1         # bypass -> 200, returns admin users JSON
```

Response on bypass: list of admin/service accounts (username, email, role, last_login).

### `/api/profile/alice` — per-character encoding

**Bug modeled:** WAF matches the raw path segment literally against a block-list of high-value user profiles. The origin decodes `%XX` before dispatching.

```http
GET /api/profile/alice HTTP/1.1                 # baseline -> 403 PII block rule
GET /api/profile/%61lice HTTP/1.1               # bypass -> 200, returns alice's profile
```

Response on bypass: full user profile (id, email, MFA status, created_at).

### `/api/tenants/acme/invoices/INV-42` — matrix-parameter suffix

**Bug modeled:** Tomcat/Jetty/Spring strip `;matrix=params` from each segment before routing. A WAF regex anchored to the literal path won't match a URL with a matrix suffix, but the servlet container still dispatches to the invoice handler.

```http
GET /api/tenants/acme/invoices/INV-42 HTTP/1.1            # baseline -> 403
GET /api/tenants/acme/invoices/INV-42;jsessionid=x HTTP/1.1  # bypass -> 200
```

Response on bypass: invoice JSON (amount, line items, status, due date).

### `/api/gateway/admin` — double-encoding

**Bug modeled:** The WAF URL-decodes once before its ACL check; the origin decodes twice (proxy + framework). A double-encoded payload passes the WAF's single-decoded view but still resolves on the origin.

```http
GET /api/gateway/admin HTTP/1.1                 # baseline -> 403 perimeter WAF
GET /api/gateway/%2561dmin HTTP/1.1             # bypass -> 200, returns gateway config
```

Response on bypass: gateway routing config, rate-limit settings, shared secret.

### `/api/audit/export` — splitter via stripped control chars

**Bug modeled:** The WAF decodes once and checks for literal substrings. The origin decodes once, then strips tab/LF/CR bytes before routing. A `%09`-tab embedded inside the protected segment decodes to a tab-containing string the WAF doesn't match, but the origin strips the tab and dispatches.

```http
GET /api/audit/export HTTP/1.1                  # baseline -> 403 deny-audit-egress
GET /api/a%09udit/export HTTP/1.1               # bypass -> 200, returns audit events
```

Response on bypass: recent audit events (actor, action, target, source IP, timestamp).

## Response markers

Successful bypass responses include:

- status `200`
- header `X-Smoke-Bypass`
- body text naming the bypass reason

Blocked responses are `403`, and unauthenticated requests are `401`.

## Notes

- `smokeTestPlaybooks` is the main smoke suite. It uses the extension's real attack classes and runs until each playbook finds a representative bypass.
- `run_smoke_tests.py` is retained as a fast black-box check for the lab itself, including the URL Validation routes.
- Several playbooks intentionally converge on the same vulnerable behavior in this lab, especially path normalization around `/api/v1/reports/export`, `/tenant/acme/billing/invoices`, and `/console/settings/users`.
- The extra `/api/v2/admin/audit` Bearer-token route is there as a realistic consultant demo even though the main `Header` playbook smoke target is the reverse-proxy route.
- The lab uses Python stdlib only, so it is easy to run locally and easy to inspect when a smoke case fails.
