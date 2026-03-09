# BypassFuzzer - Burp Suite Extension

A Burp Suite extension for testing authorization bypass vulnerabilities (401/403 bypasses). This is a Java port of the Python [BypassFuzzer](https://github.com/intrudir/BypassFuzzer) tool, fully integrated with Burp Suite.

## Features
Currently, there are 2 main bypasses we can attempt: Authorization bypasses & URL validation bypasses. When you send a request to bypass fuzzer, they are organized into 2 tabs. 


- **AuthZ Bypass Attack Types:**
  - Header-based attacks (283+ bypass headers)
  - Path manipulation (367+ URL encodings)
  - HTTP verb/method attacks (11 methods + overrides + case variations + X-prefix/suffix)
  - Debug parameter injection (31 common debug params with case variations)
  - Cookie debug parameter injection (same params as cookies + fuzz existing cookie values)
  - Trailing dot attack (absolute domain notation)
  - Trailing slash attack (tests with/without trailing slash and /. pattern)
  - Extension attack (75+ file extensions like .json, .html, .php)
  - Content-Type attack (converts between URL-encoded, JSON, XML, multipart/form-data)
  - Encoding attack (URL, double-URL, triple-URL, unicode, unicode-overflow encoding on paths, parameter names, and parameter values in query strings and all body content types)
  - HTTP protocol attacks (e.g. HTTP/1.0, HTTP/0.9)
  - Case variation attack (random capitalizations with smart limits)
- **Dedicated URL Validation Tab:**
  - Separate per-session `URL Validation` workflow beside the core bypass playbooks
  - Uses an editable request workbench with explicit `{INJECT}` marker targeting
  - Uses PortSwigger cheat-sheet-style payload families, attack settings, and encodings
  - Uses exact rendered PortSwigger payloads for the default cheat-sheet settings and appends optional advanced payload sets
  - Includes a `View Payloads` preview for the exact generated list before execution

- **Smart Filtering:** Automatically reduces noise by hiding repeated responses with pattern tracking
- **Rate Limiting & Auto-Throttling:**
  - Configurable requests per second (default: unlimited)
  - Auto-throttle when rate limit errors detected (429, 503)
  - Automatically reduces speed by 50% when throttled
- **Collaborator Integration:** Dynamic Burp Collaborator payload generation for header attacks (Burp Professional only)
- **Burp Integration:**
  - Right-click menu: "Send to BypassFuzzer"
  - Send results to Repeater/Intruder
  - Graceful shutdown and resource cleanup
- Colorize interesting requests for future filtering
- **Smoke Testing:**
  - Local vulnerable lab under `src/test/vulnerable_lab`
  - Attack-driven smoke suite that reuses the real attack classes and payload logic without Burp

## Requirements

- Java 17 or higher
- Burp Suite Professional or Community Edition (2023.10+)
- Gradle 7.0+ (for building)

## Building

```bash
# Build the extension JAR
./gradlew clean shadowJar

# The compiled JAR will be at:
# build/libs/bypassfuzzer-burp-1.0.6.jar
```

## Testing

```bash
# Unit and regression tests
./gradlew test

# Attack-driven smoke suite
./gradlew smokeTestPlaybooks
```

The smoke suite starts a local vulnerable app automatically and exercises the real attack strategies, payload expansion, registry wiring, shared executor flow, and URL Validation workflow without requiring Burp.

## Installation

1. Open Burp Suite
2. Go to **Extensions** → **Installed**
3. Click **Add**
4. Select **Extension file**: `bypassfuzzer-burp-1.0.6.jar`
5. Click **Next**
6. The extension will load and a "BypassFuzzer" tab will appear

## Usage

### Basic Workflow

1. **Send Request to BypassFuzzer:**
   - Right-click any request in Proxy, Target, or Repeater
   - Select "Send to BypassFuzzer"

2. **Choose Session Mode:**
   - `Bypass` for the core AuthZ bypass playbooks
   - `URL Validation` for marker-driven URL validation testing

3. **Configure Attack:**
   - In `Bypass`, select attack types to enable (or use Check All/Uncheck All)
   - Optionally enable Collaborator payloads (Burp Professional only)
   - Configure rate limiting:
     - Set requests/second (0 = unlimited, default)
     - Configure auto-throttle status codes (default: 429, 503)
   - In `URL Validation`:
     - edit the base request directly in the request workbench
     - place `{INJECT}` where payloads should go
     - set the allowed host, attacker host, and scheme
     - choose the payload families to run: `Absolute URL`, `Host header`, and/or `CORS`
     - default family selection matches the cheat sheet more closely: `Absolute URL` only
     - choose the attack settings to include:
       - `Domain allow list bypass`, `Fake relative URLs`, `Loopback`, `IPv6`, `Cloud metadata endpoints`, `URL-splitting Unicode characters`
     - choose one encoding mode: `Raw`, `Intruder's`, `Everything`, `Special chars`, or `Unicode escape`
     - use `View Payloads` to inspect the exact generated list before starting

4. **Start Fuzzing:**
   - Click the mode-specific start button
   - Results appear in real-time, filtered with your criteria in real-time
   - Can stop fuzzing at any time with the mode-specific `Stop` button
   - Auto-throttle will activate if rate limit errors detected
   - Can right click a request to color it for identification/filtering later

5. **Review Results:**
   - Dynamic filtering based on status codes, length, content-type, etc.
   - Use smart filter to see only interesting results automatically
   - `URL Validation` results show `Target`, `Family`, `Encoding`, and the final injected `Payload`
   - Click any result to view full request/response
   - Send interesting findings to Repeater or Intruder

6. **Scan History:**
   - Export results to CSV/JSON (TODO)

## Vulnerable Lab

For manual Burp validation and local attack smoke tests, use the vulnerable app in [`src/test/vulnerable_lab`](src/test/vulnerable_lab).

Manual run:

```bash
python3 src/test/vulnerable_lab/app.py
```

Then:

1. Request `GET /login` to receive `session=lab-user`
2. Use `/edge/private/reports/quarterly`, `/api/v1/reports/export`, `/tenant/acme/billing/invoices`, `/console/settings/users`, `/rest/admin/users/42`, `/api/internal/runtime/config`, `/portal/account/export`, `/edge/admin/console`, `/graphql/internal/preferences`, `/api/v2/admin/audit`, `/legacy/admin/audit`, `/redirect/next`, `/host/check`, and `/cors/profile` as base targets
3. Run the extension against those requests or execute `./gradlew smokeTestPlaybooks`

For `URL Validation`, edit the request first and replace the URL-like value with `{INJECT}`. Example:

```http
GET /redirect/next?next={INJECT} HTTP/1.1
Host: 127.0.0.1:8008
Cookie: session=lab-user
```

For CORS-style checks, put the marker directly in the `Origin` header:

```http
GET /cors/profile HTTP/1.1
Host: 127.0.0.1:8008
Origin: {INJECT}
Cookie: session=lab-user
```

Then choose the `CORS` payload family in `Configure Attack` before starting the run.

Defaults are aligned with the PortSwigger cheat sheet as closely as practical in this UI:

- payload family: `Absolute URL`
- attack settings: `Domain allow list bypass`, `Fake relative URLs`, `Loopback`
- encoding: `Intruder's`

Encoding behavior follows the selected dropdown mode, one at a time.

Real-world-style examples in the lab include:

- reverse-proxy header trust on `/edge/private/reports/quarterly`, where `X-Forwarded-For`, `X-Custom-IP-Authorization`, `X-Original-URL`, or `X-Rewrite-URL` can incorrectly punch through an edge-protected report route
- nested report and billing routes that return `403` until a path-normalization payload collapses them back to the protected backend path
- a weak Bearer-token admin route on `/api/v2/admin/audit` that returns `403` for a normal user token and is bypassed because token shape is checked more than token validity
- separate consultant-demo routes for method confusion, truthy query parameters, truthy cookies, trailing-dot host routing, content-type parser confusion, and HTTP/1.0 downgrade handling
- the existing URL-validation examples for redirect, host, and CORS trust decisions

The detailed route matrix and black-box lab checks are documented in [`src/test/vulnerable_lab/README.md`](src/test/vulnerable_lab/README.md).

## Custom Payloads

You can edit the payload files before building. UI config for this will be added in a future release.

1. **Header Templates:** One template per line, use placeholders:
   - `{IP PAYLOAD}` - Replaced with IP addresses from ip_payloads.txt
   - `{URL PAYLOAD}` - Replaced with full target URL
   - `{PATH PAYLOAD}` - Replaced with URL path only
   - `{PATH SWAP}` - For URL-based access control bypasses; puts original path in header and swaps request path to `/`
   - `{OOB PAYLOAD}` - Dynamically generates Burp Collaborator payload (http:// and https:// URLs)
   - `{OOB DOMAIN PAYLOAD}` - Dynamically generates Burp Collaborator domain only
   - `{WHITESPACE PAYLOAD}` - Replaced with whitespace character

   Example: `X-Forwarded-For: {IP PAYLOAD}`
   Example with Collaborator: `X-Forwarded-For: {OOB DOMAIN PAYLOAD}`
   Example for URL bypass: `X-Original-URL: {PATH SWAP}` (sends `GET /` with header `X-Original-URL: /edge/private/reports/quarterly`)

2. **IP Payloads:** One IP address per line

   Example: `127.0.0.1`

3. **URL Payloads:** One URL encoding/pattern per line

   Example: `/../`

4. **Parameter Payloads:** One parameter=value per line

   Example: `debug=true`

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

- Original Python tool: [@intrudir](https://twitter.com/intrudir)
- Smart filter algorithm: [@defparam](https://twitter.com/defparam)
- Unicode overflow technique: [PortSwigger Research](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows)
