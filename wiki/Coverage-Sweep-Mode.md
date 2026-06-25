# Coverage Sweep Mode

The `Sweep` tab is the broad coverage mode for BypassFuzzer.

It is designed for the case where an assessment has many blocked endpoints in Burp Proxy history and the tester wants a bounded, high-signal check across them. It is not a full scanner and it does not run the full Bypass playbooks against every endpoint.

## When To Use It

Use Sweep when:

- Proxy history contains in-scope `401` or `403` responses
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

Sweep loads candidates from Burp Proxy history.

By default it selects:

- `401`
- `403`

The UI also allows opt-in loading of:

- `3xx`
- `4xx`

Only in-scope Proxy history items are loaded.

## Deduplication

Sweep deduplicates candidates before previewing or sending probes.

The dedupe key includes:

- scheme, host, and port
- HTTP method
- normalized path shape
- sorted query parameter names
- request `Content-Type`

When multiple history items match the same dedupe key, Sweep keeps the most recent request.

## Probe Budget

Sweep uses a bounded probe set with a default cap of 50 unique probes per endpoint.

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
PATH|Debug Params|Append debug=true|{PATH}{QUERY}{QUERY_APPEND_SEPARATOR}debug=true
HEADER|Header|Authorization bearer placeholder|Authorization: Bearer A
```

The supported placeholders are documented at the top of the wordlist.

## Current Probe Families

The default Sweep probes focus on:

- matrix and extension normalization
- lightweight content negotiation query probes
- trailing slash toggle
- dot-segment and encoded-dot suffixes
- encoded and double-encoded dot-segment prefixes and suffixes
- prefix double and triple slash variants
- internal duplicate slash variants
- first-segment and last-segment uppercase variants
- capitalized and mixed-case path variants
- selected URL-encoded path characters
- selected debug parameters
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
