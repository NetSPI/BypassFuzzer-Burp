# Coverage Sweep Mode

The `Sweep` tab is the broad coverage mode for BypassFuzzer.

It is designed for the case where an assessment has many blocked endpoints in Burp Proxy history, or a curated text file of target URLs, and the tester wants a bounded, high-signal check across them. It is not a full scanner and it does not run the full Bypass playbooks against every endpoint.

## When To Use It

Use Sweep when:

- Proxy history contains in-scope `401` or `403` responses
- you have a `.txt` file with one absolute target URL per line
- you want a quick coverage pass across many blocked endpoints
- you want to check common path-normalization and lightweight header cases without sending thousands of requests per endpoint

Use a targeted request tab instead when:

- one endpoint deserves deeper testing
- you want the full AuthZ bypass playbooks
- you want IDOR/BOLA mutation against a known object identifier
- you need URL validation payload generation with `{INJECT}` markers

## Startup Behavior

Sweep is available immediately when the extension loads.

The top-level extension tabs are:

- `Welcome`
- `Sweep`
- one tab per targeted request sent to BypassFuzzer

Targeted request tabs contain:

- `Bypass`
- `IDOR`
- `URL Validation`

## Candidate Collection

Sweep loads candidates from Burp Proxy history or an imported target list.

Sweep has three source modes:

- `Blocked responses` loads the configured blocked/error status codes and compares probes with a live control request.
- `Authenticated traffic` passively loads in-scope `2xx` history, identifies requests using user-selected auth header or cookie names, strips authentication, and sends only mutated probes.
- `Import targets` shows the import control and loads a `.txt` file containing one absolute URL per line.

The Proxy-history load control is shown only for the two history modes. `Import Targets` is shown only in import mode. Response-status filters are shown only in `Blocked responses`.
Proxy-history discovery runs in the background so large authenticated history sets do not block Burp's interface.
When automatic HTTP negotiation returns no response, Sweep retries safe `GET` and `HEAD` probes over HTTP/1. Remaining transport failures stay visible as `No response` rows and are written to the extension error log with the affected method and URL.

By default it selects:

- `401`
- `403`

The UI also allows opt-in loading of:

- `3xx`
- `4xx`

Only in-scope Proxy history items are loaded.

Imported target files use one absolute URL per line:

```text
https://victim.com/admin/users
https://victim.com/admin/info
```

Blank lines, comment lines beginning with `#`, and invalid URLs are ignored. Imported targets are deduplicated and shown in the preview table before Sweep sends any requests. `View` opens the selected request and response side by side in a resizable window. The response side remains empty for imported URLs until the Control request runs because a URL list contains no stored response.
Imported targets are unavailable in authenticated-traffic mode because they have no stored authenticated request or response.

## Authenticated Traffic

Authenticated-traffic discovery does not send requests. It inspects Proxy history and inventories likely authentication header names and cookie names without displaying their values. `Authorization` and session/auth/token-like identifiers are selected automatically; the tester can change the selection and add custom auth header names.

A `2xx` history request is included when it contains at least one selected identifier. `GET` and `HEAD` are included by default. State-changing methods require the explicit `Include state-changing methods` option.

Images, JavaScript, CSS, and WOFF/WOFF2 responses are excluded by default using their response `Content-Type` or request-path extension. Clear `Exclude static assets` before loading authenticated history when those resources should be included.

Cookie selections are identifiers only. Before attacks are generated, Sweep removes:

- the entire `Cookie` header
- `Authorization`
- `Proxy-Authorization`
- additional auth headers selected by the tester

Sweep does not replay the authenticated request and does not send an unmodified anonymous control. It applies the existing bounded probe inventory to the stripped request and displays every response without labeling it a bypass. `View` shows the selected candidate's stored authenticated exchange for manual comparison. Imported targets use their generated request and live Control response there. The scan-results viewer contains only the mutated `Request` and `Response`.

## Deduplication

Sweep deduplicates candidates before previewing or sending probes.

The dedupe key includes:

- scheme, host, and port
- HTTP method
- normalized path shape
- sorted query parameter names
- request `Content-Type`

When multiple history items match the same dedupe key, Sweep keeps the most recent request.

## Execution Controls

Sweep runs one candidate sequentially, but can run multiple candidates concurrently.

- `Concurrency` controls how many endpoints can be swept at the same time; the default is `1`.
- `Delay (ms)` spaces request starts globally across all concurrent workers.
- `Throttle codes` defaults to `429,503`; a matching response immediately pushes the shared request gate forward.
- Adaptive throttling honors `Retry-After`, increases on recurring throttle responses, and gradually recovers after clean-response quiet windows.

## Probe Budget

Sweep uses a bounded probe set with a default cap of 120 unique probes per endpoint.

Generated requests are deduplicated before sending. This matters for short paths such as `/admin`, where some templates collapse to the same effective request:

```text
//admin
///admin
```

For longer paths such as `/admin/users`, prefix slash probes and internal duplicate slash probes are distinct:

```text
//admin/users
///admin/users
/admin//users
/admin///users
```

## Probe Wordlist

Sweep probes are controlled by one explicit build-time wordlist:

```text
src/main/resources/payloads/sweep_probes.txt
```

The wordlist is intentionally visible and simple. Rows are either `PATH` or `HEADER` templates.

Examples:

```text
PATH|Matrix / Extension|Path suffix ;.json|{PATH};.json{QUERY}
PATH|Path Normalization|Uppercase first segment|{PATH_FIRST_SEGMENT_UPPERCASE}
PATH|Path Normalization|Uppercase last segment|{PATH_LAST_SEGMENT_UPPERCASE}
PATH|Encoding|Double URL encode path character 1|{PATH_DOUBLE_URL_ENCODE_CHAR_1}
PATH|Debug Params|Append debug=true|{PATH}{QUERY}{QUERY_APPEND_SEPARATOR}debug=true
HEADER|Content-Type|Content-Type application/json|Content-Type: application/json
HEADER|Header|Authorization bearer placeholder|Authorization: Bearer A
```

The supported placeholders are documented at the top of the wordlist.

## Current Probe Families

The default Sweep probes focus on:

- matrix and extension normalization
- lightweight content negotiation query probes
- framework and extension fallback suffixes
- trailing slash toggle
- dot-segment and encoded-dot suffixes
- encoded and double-encoded dot-segment prefixes and suffixes
- prefix double and triple slash variants
- internal duplicate slash variants
- first-segment and last-segment uppercase variants
- capitalized and mixed-case path variants
- selected URL-encoded path characters
- selected double URL-encoded path characters
- selected encoded path separators and fully encoded segments
- selected debug parameters
- selected `Content-Type` header mutations
- selected lightweight header probes

## Preview

The `Preview Probes` button shows the exact requests that Sweep will send for the selected candidate.

Preview does not send traffic.

It uses the same generator path as execution, so it is the source of truth for what will run.

## Signals

Sweep shows all responses, but the `Signal` column is only populated for interesting changes.

Examples:

```text
403 -> 200
401 -> 302
Content-Type text/html -> application/json
Length +347
```

Probe responses with `4xx` status codes are still shown, but they do not receive a signal. This avoids noisy cases such as a redirect baseline becoming a larger `404` page.

## Design Intent

Sweep is meant to close broad coverage gaps without becoming a hail-mary scanner.

It should:

- cover many blocked endpoints quickly
- send a small number of high-signal probes per endpoint
- make the exact probe inventory obvious to the developer
- require preview before execution
- avoid hiding request volume behind broad playbook expansion

It should not:

- scan the entire application blindly
- run thousands of payload combinations per endpoint
- replace targeted Bypass, IDOR, or URL Validation testing
