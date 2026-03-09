# URL Validation Bypass Feature Plan

## Status Note

This document started as the original design plan. Large parts of it are now historical. The shipped implementation is cheat-sheet-driven and differs from several of the earlier design ideas below.

Current implementation:

- uses explicit `{INJECT}` markers in the edited request
- does not expose auto-detect targeting in the UI
- exposes payload-family checkboxes in the UI:
  - `Absolute URL`
  - `Host header`
  - `CORS`
- defaults to `Absolute URL`
- exposes attack-setting checkboxes in the UI:
  - `Domain allow list bypass`
  - `Fake relative URLs`
  - `Loopback`
  - `IPv6`
  - `Cloud metadata endpoints`
  - `URL-splitting Unicode characters`
- defaults to:
  - payload family: `Absolute URL`
  - attack settings: `Domain allow list bypass`, `Fake relative URLs`, `Loopback`
  - encoding: `Intruder's`
- uses one encoding dropdown at a time:
  - `Raw`
  - `Intruder's`
  - `Everything`
  - `Special chars`
  - `Unicode escape`
- includes a `View Payloads` preview in the config dialog
- uses exact rendered PortSwigger payloads for the default attack settings and appends optional advanced payload sets from bundled source data
- labels results with structured metadata such as `Target`, `Family`, `Encoding`, and final injected `Payload`

Treat sections below that describe auto-detect targeting, hidden family selection, sink-name injection fallback, or old encoding controls as historical design notes rather than the current product behavior.

## Summary

Add a new attack playbook named `URL Validation` that generates and injects URL validation bypass payloads anywhere the target application accepts a URL, host, origin, or redirect target.

This is intentionally broader than SSRF. The same payload families help test:

- SSRF
- open redirect
- CORS origin validation
- webhook / callback URL allowlists
- host / origin trust decisions
- any server-side or client-side URL allowlist / parser discrepancy

Primary external references:

- PortSwigger Web Security Academy: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- PortSwigger Research: https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet
- PortSwigger Research update: https://portswigger.net/research/new-crazy-payloads-in-the-url-validation-bypass-cheat-sheet

## Problem

The current extension has strong coverage for access-control bypasses based on:

- path rewriting
- header trust
- method confusion
- parameter and cookie toggles
- protocol / encoding / extension tricks

What it does not cover well is a common modern trust boundary: "this value must point to a trusted URL, host, or origin".

That gap matters because applications often:

- fetch attacker-controlled URLs
- redirect to attacker-controlled URLs
- reflect or compare `Origin` / `Referer`
- validate callback URLs with weak allowlist logic
- compare strings using one parser and fetch using another

These are not purely SSRF problems. They are URL validation problems.

## Goals

- Add first-class URL validation bypass testing without requiring the user to manually curate payloads.
- Reuse one payload engine across SSRF, CORS, open redirect, and URL allowlist testing.
- Fit the current extension architecture:
  - attack registry
  - `AttackStrategy`
  - shared `AttackExecutor`
  - payload repository pattern
  - smoke lab / attack-driven smoke suite
- Keep request volume controllable. The payload set must be targeted, not combinatorial explosion by default.

## Non-Goals

- Do not turn BypassFuzzer into a crawler or active SSRF scanner.
- Do not automatically follow redirects or perform browser validation.
- Do not implement Collaborator polling or OAST workflow in this feature phase.
- Do not try to mirror the entire PortSwigger cheat sheet UI one-for-one inside Burp.

## Product Shape

### Session UX

Do not add `URL Validation` as another checkbox in the main bypass attack list.

Instead, extend the existing session flow like this:

1. `Send to BypassFuzzer`
2. open the normal BypassFuzzer session tab
3. inside that session, show a second tab layer:
   - `Bypass`
   - `URL Validation`

Reason:

- URL validation testing has a different workflow than the existing access-control bypass playbooks
- it needs different inputs
- it needs different sink discovery logic
- it benefits from its own results interpretation and controls

### Bypass Tab

The existing attack selection flow stays under the `Bypass` tab.

### URL Validation Tab

The new `URL Validation` tab is a dedicated workflow that:

- lets the user edit the base request directly
- requires explicit marker targeting such as `{INJECT}`
- runs a URL-specific mutation engine
- lets the user choose payload families, attack settings, and one encoding mode
- lets the user preview the exact payload list before execution
- renders URL-validation-specific results

The implementation may still use a dedicated backend attack type or strategy, but the UI should expose it as its own session tab, not as a checkbox in the bypass list.

### Payload Families

The current product exposes payload families directly in the UI:

1. `Absolute URL`
2. `Host header`
3. `CORS`

The consultant marks likely URL-like inputs with `{INJECT}` and explicitly chooses which families to run.

Historical note:

- older design text below assumes the tool would infer or hide family selection
- the current UI does not do that

## Detection Model

Historical note:

- the current implementation does not auto-detect sinks by name or value
- it only mutates explicit `{INJECT}` markers in the edited request
- the sections below describe the original discovery model that was considered earlier
The playbook should not mutate every string blindly. It should target likely URL sinks using two mechanisms.

### 1. Name-Based Detection

Target parameters / headers / cookies whose names suggest URL semantics.

Initial allowlist:

- `url`
- `uri`
- `dest`
- `destination`
- `redirect`
- `redirect_url`
- `redirect_uri`
- `return`
- `return_to`
- `returnurl`
- `returnuri`
- `next`
- `continue`
- `callback`
- `callback_url`
- `webhook`
- `feed`
- `link`
- `image`
- `avatar`
- `origin`
- `referer`
- `referrer`
- `host`
- `domain`
- `endpoint`

### 2. Value-Based Detection

If the existing value looks like one of the following, treat it as a candidate even if the name is generic:

- absolute URL: `http://...`, `https://...`
- scheme-relative URL: `//...`
- browser origin: `scheme://host[:port]`
- hostname-like value: `example.com`, `localhost`, IPv4, IPv6
- path-like redirect target: `/login`, `/callback`, `/oauth/complete`

This keeps the playbook useful on real applications with inconsistent naming.

## Mutation Points

The playbook should mutate the following request locations:

- query parameters
- form body parameters
- JSON body fields
- XML body fields
- multipart form fields
- cookies when the cookie value itself is a URL sink
- selected headers:
  - `Origin`
  - `Referer`
  - `X-Forwarded-Host`
  - `Host`
  - optionally `X-Original-URL` and `X-Rewrite-URL` for URL-valued use cases

It should not mutate arbitrary browser noise headers by default.

## Payload Engine Design

### Overview

Introduce a dedicated payload generator rather than hard-coding strings inside the attack class.

Proposed classes:

- `UrlValidationAttack`
- `UrlValidationPayloadGenerator`
- `UrlValidationOptions`
- `UrlValidationAttackSetting`
- `UrlValidationContext`
- `UrlValidationCandidate`

### Context Enum

```java
enum UrlValidationContext {
    ABSOLUTE_URL,
    HOSTNAME,
    CORS_ORIGIN
}
```

### Candidate Model

```java
record UrlValidationCandidate(
    String name,
    String originalValue,
    ParameterLocation location,
    UrlValidationContext context
) {}
```

For headers, either extend `ParameterLocation` or introduce a small parallel location enum specific to this playbook.

### Payload Categories

The generator should group payloads by category so we can keep defaults tight and optionally expose advanced toggles later.

Initial categories:

1. `Domain allowlist bypass`
   - suffix confusion
   - prefix confusion
   - subdomain confusion
   - userinfo `@`
   - fragment / query tricks
2. `Loopback / internal address`
   - localhost
   - IPv4 alternatives
   - IPv6 / IPv4-mapped IPv6
   - decimal / octal / hex / mixed forms
3. `Fake relative URL`
   - browser-valid but validator-confusing forms
4. `Normalization / invisible characters`
   - zero-width
   - soft hyphen
   - unicode separator tricks
5. `Encoding`
   - percent-encoding
   - intruder-friendly percent-encoding
   - unicode escape
6. `Origin-specific`
   - valid origin strings aimed at CORS trust logic

### Seed Inputs

The payload generator needs three user-configurable values:

- `allowedHost`
- `attackerHost`
- `attackerScheme`

Defaults:

- `attackerHost = 127.0.0.1`
- `attackerScheme = https`
- `allowedHost` inferred from the current request host when possible

If the candidate already contains a host, that host can seed "allowed domain" mutations automatically.

### Phase 1 Payload Scope

Phase 1 should not try to import every cheat-sheet permutation.

Recommended initial subset:

- straightforward allowlist-confusion payloads
- loopback / internal-host representations
- `@` userinfo payloads
- fake-relative URL forms
- percent-encoded and double-encoded variants
- selected normalization payloads with demonstrated value
- CORS-origin-safe variants

This keeps the request count reasonable and gives room to grow.

### Phase 2 Payload Expansion

Phase 2 can import richer PortSwigger-derived sets, including:

- partial decimal class A / class B IP forms
- mixed radix encodings
- IPv6 expanded and mapped forms
- userinfo left-square-bracket discrepancy payloads from the 2024 update
- additional CORS domain-splitting edge cases

## Request Mutation Semantics

Current behavior:

- the user edits the exact request in the request workbench
- the engine replaces explicit `{INJECT}` markers in that edited request
- the tool does not add inferred sink names or inject fallback parameters automatically
- if multiple markers exist, each marker occurrence is replaced during each generated request mutation

The goal is realistic validation-bypass traffic, not gratuitous request corruption.

## UI / UX Design

### Session Layout

Add an inner `JTabbedPane` within `FuzzingSessionTab`:

- `Bypass`
- `URL Validation`

The existing attack selection controls remain on `Bypass`.

Add a dedicated `UrlValidationPanel` for the new tab.

### URL Validation Panel

The `UrlValidationPanel` should contain:

- a filter sidebar on the left
- a URL-validation results table with request/response viewers
- a `Configure Attack` dialog that contains:
  - host inputs
  - payload-family selection
  - attack-setting selection
  - encoding selection
  - the request workbench
  - `View Payloads`
- run / stop controls

### URL Validation Options

Fields:

- `Allowed Host`
- `Attacker Host`
- `Attacker Scheme`
- checkboxes:
  - `Absolute URL`
  - `Host header`
  - `CORS`
  - `Domain allow list bypass`
  - `Fake relative URLs`
  - `Loopback`
  - `IPv6`
  - `Cloud metadata endpoints`
  - `URL-splitting Unicode characters`
- dropdown:
  - `Raw`
  - `Intruder's`
  - `Everything`
  - `Special chars`
  - `Unicode escape`
- action:
  - `View Payloads`

Default values:

- infer `Allowed Host` from target host
- `Attacker Host = 127.0.0.1`
- `Attacker Scheme = https`
- `Absolute URL` enabled
- `Host header` disabled
- `CORS` disabled
- `Domain allow list bypass`, `Fake relative URLs`, and `Loopback` enabled
- `IPv6`, `Cloud metadata endpoints`, and `URL-splitting Unicode characters` disabled
- `Encoding = Intruder's`

### Payload Transparency

The result payload column should clearly show:

- target label
- family
- encoding
- final mutated value

Example:

- `marker [Absolute URL][Intruder's]: https://trusted.example%40127.0.0.1/`

## Config Changes

Historical note:

- the config sketch below predates the current implementation
- the shipped feature uses a dedicated `UrlValidationPanel` and `UrlValidationOptionsPanel`
- it no longer uses the older inject-common-sinks or hidden-context model described here

## Code Design

### Backend Entry Point

Add a dedicated backend strategy for this tab:

- `UrlValidationAttack`

This can still map to a new internal `AttackType` if that simplifies orchestration, labeling, and results handling, but the UI must expose it as its own session tab rather than a checkbox in `AttackSelectionPanel`.

### New Payload Package

Current implementation uses:

- `UrlValidationPayloadGenerator`
- `UrlValidationOptions`
- `UrlValidationAttackSetting`
- `UrlValidationContext`

Bundled payload resources live under `src/main/resources/payloads/`:

- `url_validation_cheatsheet.json`
- `url_validation_source_data.json`

The generator uses the rendered cheat-sheet dataset for the default PortSwigger settings and appends optional advanced payloads from the bundled source dataset.

### UI Components

Add under `ui/session`:

- `UrlValidationPanel`
- optionally `UrlValidationResultsPanel`
- optionally `UrlValidationOptionsPanel`

`FuzzingSessionTab` becomes the composition root that hosts:

- `Bypass` tab content
- `URL Validation` tab content

### New HTTP Helpers

Add focused helpers rather than bloating existing ones:

- `UrlCandidateDetector`
- `HeaderUrlCandidateDetector`
- possibly `BodyFieldMutationSupport` if JSON/XML body mutation becomes repetitive

Avoid turning `RequestParameterSupport` into a catch-all dumping ground.

## Results and Filtering

No major filter changes are required for Phase 1.

Optional improvements later:

- filter by `payload category`
- highlight `URL Validation` results with `200`, `30x`, or changed `Access-Control-Allow-Origin`

## Smoke Lab Design

Extend the existing smoke lab with routes that validate URL-like fields incorrectly.

Add representative vulnerable cases:

1. `GET /redirect?next=...`
   - vulnerable to open redirect via allowlist confusion
2. `POST /api/fetch`
   - vulnerable to URL allowlist bypass on a body field like `url`
   - returns `200` and `X-Smoke-Bypass` when payload resolves to localhost / loopback form
3. `OPTIONS /cors/profile`
   - reflects trusted `Origin` only if weak validation passes
   - vulnerable to origin confusion payloads
4. `POST /webhook/validate`
   - validates callback URL with weak hostname allowlist

Markers:

- `open-redirect`
- `url-allowlist-bypass`
- `cors-origin-bypass`
- `loopback-host-bypass`

## Smoke Suite Design

Extend `AttackPlaybookSmokeTest` with:

- one smoke scenario for `URL Validation` query param sink
- one for body sink
- one for `Origin`

The attack-driven smoke suite should:

- instantiate the real `UrlValidationAttack`
- use the real payload generator
- stop once at least one representative success marker is observed

## Testing Strategy

### Unit Tests

Add focused tests for:

- candidate detection by name
- candidate detection by value
- context classification
- payload generation by category
- loopback encoding generation
- normalization payload generation

### Attack Tests

Add tests that assert:

- query sink mutation preserves parameter name
- JSON body sink mutation preserves surrounding structure
- `Origin` / `Host` overwrite semantics are correct
- request count stays bounded with default settings

### Smoke Tests

Add attack-driven smoke coverage against the local lab for:

- open redirect sink
- fetch / callback sink
- CORS origin sink

## Phased Rollout

### Phase 1

- new `URL Validation` session tab
- explicit marker targeting
- payload families, attack settings, and encoding selection
- cheat-sheet-backed payload generation
- `View Payloads` preview
- smoke lab + smoke suite

### Phase 2

- richer PortSwigger-derived payload import
- additional attack-setting parity if PortSwigger expands its source data
- result-category filters
- optional Collaborator integration for URL sinks used in SSRF-style workflows

## Risks

### Request Volume

This feature can easily explode request counts if every candidate gets every payload.

Mitigation:

- cap default payload set
- stop at a sane maximum per sink
- optional advanced mode for full sets later

### False Positives

Applications may accept weird URLs syntactically but never use them meaningfully.

Mitigation:

- show sink name and category clearly
- rely on status / length / content markers
- preserve current filter workflow

### Overlap With Existing Attacks

Some `Header`, `Param`, and `Content-Type` attacks already touch URL-like values indirectly.

Mitigation:

- keep `URL Validation` focused on URL-bearing sinks
- do not duplicate generic path or header trust payloads unless they specifically target URL parsing logic

## Recommendation

Implement this as a dedicated new session tab, not as an SSRF mode and not as a hidden expansion of existing attacks.

Reason:

- the problem domain is broader than SSRF
- the PortSwigger source material is explicitly about URL validation, not one vulnerability class
- a dedicated playbook keeps the UX understandable
- a shared payload engine can still be reused later by other attack types

## Definition of Done

- session UI exposes a dedicated `URL Validation` tab
- the existing bypass attack list remains focused and unchanged
- the attack mutates explicit `{INJECT}` markers in the edited request
- the smoke lab has representative URL validation vulnerabilities
- `./gradlew smokeTestPlaybooks` includes `URL Validation`
- docs explain scope as URL validation bypass, not SSRF only
