# Playbooks Overview

This page describes how BypassFuzzer organizes playbooks today.

## Philosophy

The tool is most maintainable when we centralize the framework and keep the testing ideas clearly named.

That means:

- shared execution and orchestration live in engines, controllers, and registries
- concrete testing ideas live as named playbooks or attack types
- docs should refer to the same stable names the code uses

## AuthZ Bypass

The main bypass tab is driven by `AttackRegistry`.

Each enabled `AttackType` maps to one concrete strategy class, for example:

- `HEADER` -> `HeaderAttack`
- `PATH` -> `PathAttack`
- `CONTENT_TYPE` -> `ContentTypeAttack`
- `ENCODING` -> `EncodingAttack`

This part of the codebase is best thought of as:

- a shared execution layer
- a curated set of authorization bypass technique families

## URL Validation

The URL validation tab is marker-driven.

The user marks injection points with a token such as `{INJECT}`. The tool then expands payloads using:

- `UrlValidationContext`
  Where the payload is meant to work, such as absolute URLs, hostnames, or CORS origins.
- `UrlValidationAttackSetting`
  The payload category, such as domain allow-list bypasses or loopback tricks.
- `UrlValidationEncoding`
  How the payload should be encoded before insertion.

This area is more payload-generation-driven than attack-registry-driven.

## IDOR / BOLA

The IDOR tab uses explicit playbooks under `core/idor/playbooks`.

Each playbook:

- has a stable ID
- has a display name
- has a short description
- emits concrete request variants

This makes the technique families easy to identify in results and easy to extend later.

## Current IDOR Naming Scheme

- `idor.path.*`
  Path and route-shape manipulation around the object identifier.
- `idor.query.*`
  Conflicting or duplicate identifier sources in the query string.
- `idor.hybrid.*`
  Carefully selected ideas borrowed from the AuthZ bypass tab that are also useful in an IDOR context.

## Documentation Rule

Whenever we add a new playbook or technique family, we should document:

- the stable ID or enum name
- why it exists
- what mutations it performs
- what kinds of findings it is trying to surface
