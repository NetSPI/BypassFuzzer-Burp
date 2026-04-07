# URL Validation Playbooks

The `URL Validation` tab is for marker-driven URL validation and allow-list bypass testing.

The main payload generation flow lives in `src/main/java/com/bypassfuzzer/burp/core/urlvalidation/UrlValidationPayloadGenerator.java`.

## Why This Is In The Tool

Applications frequently accept user-controlled URLs, hosts, or origins and then try to validate them.

Those validation layers often fail because:

- they parse a URL differently from the component that later uses it
- they only validate part of the input
- they mishandle encoding
- they allow loopback, metadata, or attacker-controlled routing tricks

This tab exists to turn those families into repeatable, reviewable payload sets.

## How It Works

1. The user marks one or more injection points in a request, usually with `{INJECT}`.
2. The generator expands payloads using selected contexts, settings, and encodings.
3. Each marker is replaced with concrete payloads.
4. The results are emitted into the same session/results workflow as the other tabs.

## Payload Families

These are modeled by `UrlValidationContext`.

### `Absolute URL`

Payloads shaped like full URLs.

Use when:
The target expects a complete URL, redirect target, callback URL, SSRF target, or similar value.

### `Host header`

Payloads shaped like hostnames.

Use when:
The target validates only a host value rather than a full URL.

### `CORS`

Payloads shaped for `Origin` and CORS validation scenarios.

Use when:
The application is making trust decisions based on origin matching.

## Payload Categories

These are modeled by `UrlValidationAttackSetting`.

### `Domain allow list bypass`

Targets applications that trust a URL or host because it appears to match an allowed domain.

### `Fake relative URLs`

Targets parsers that misread authority, slashes, or relative-looking payloads.

### `Loopback`

Targets applications that accidentally permit localhost or loopback destinations.

### `IPv6`

Targets parsing differences between IPv4-style and IPv6-style host representations.

### `Cloud metadata endpoints`

Targets SSRF-sensitive environments where metadata endpoints may be reachable.

### `URL-splitting Unicode characters`

Targets parsers that split or normalize Unicode characters inconsistently.

## Encoding Modes

The generator can render payloads in different encodings before insertion.

Why:
Some validators inspect raw input while downstream components decode it one or more times.

## Notes

- This area is payload-family-driven rather than attack-type-driven.
- The source payloads are bundled resources rather than hardcoded inline lists.
- The current implementation is intentionally aligned with the PortSwigger URL validation bypass cheatsheet model.
