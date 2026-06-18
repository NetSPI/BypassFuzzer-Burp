# BypassFuzzer Wiki

This wiki is the documentation source for BypassFuzzer's testing playbooks.

The goal is to make it easy to answer four questions:

1. What testing areas does the extension cover?
2. Why is a given playbook in the tool?
3. What does that playbook actually try?
4. Where should we add new techniques later?

## Sections

- [Playbooks Overview](Playbooks-Overview)
- [Coverage Sweep Mode](Coverage-Sweep-Mode)
- [AuthZ Bypass Playbooks](AuthZ-Bypass-Playbooks)
- [URL Validation Playbooks](URL-Validation-Playbooks)
- [IDOR-BOLA Playbooks](IDOR-BOLA-Playbooks)
- [Adding New Playbooks](Adding-New-Playbooks)

## Current Model

BypassFuzzer currently has four main testing areas:

- `Sweep`
  Broad, bounded coverage for in-scope blocked endpoints pulled from Burp Proxy history, driven by `src/main/java/com/bypassfuzzer/burp/core/coverage/CoverageSweepEngine.java`.
- `Bypass`
  AuthZ and access-control bypass testing driven by the attack registry in `src/main/java/com/bypassfuzzer/burp/core/attacks/AttackRegistry.java`.
- `URL Validation`
  Marker-driven URL validation and SSRF-style allow-list bypass testing driven by `src/main/java/com/bypassfuzzer/burp/core/urlvalidation/UrlValidationPayloadGenerator.java`.
- `IDOR`
  Object-identifier manipulation and BOLA testing driven by `src/main/java/com/bypassfuzzer/burp/core/idor/playbooks/IdorPlaybookRegistry.java`.

## Naming Conventions

The docs use the same naming model as the code:

- `AttackType`
  Top-level AuthZ bypass techniques.
- `CoverageSweepProbe`
  Bounded Sweep probe templates generated from `src/main/resources/payloads/sweep_probes.txt`.
- `UrlValidationContext` and `UrlValidationAttackSetting`
  Payload families and payload categories for URL validation.
- `IdorPlaybook`
  Named IDOR/BOLA technique families with stable IDs.

## Why Keep This In Git?

- It keeps the playbook docs versioned with the code.
- It makes future additions easier because the code and the rationale live together.
- It gives us a clean source we can later mirror into a hosted GitHub wiki if we want.
