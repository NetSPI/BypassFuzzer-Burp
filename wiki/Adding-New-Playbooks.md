# Adding New Playbooks

This page is the maintenance guide for adding new techniques to BypassFuzzer.

## General Rule

Add new techniques as named, documented units instead of burying them inside a large engine method.

That keeps three things healthy:

- code review
- future maintenance
- documentation

## AuthZ Bypass

Add new bypass techniques through the attack registry.

Typical steps:

1. Add or update the concrete strategy class under `src/main/java/com/bypassfuzzer/burp/core/attacks/`.
2. If needed, add a new `AttackType`.
3. Register the strategy in `AttackRegistry`.
4. Document the new attack family in `AuthZ-Bypass-Playbooks`.

Use this path when the technique is a general authorization-bypass family rather than a specific object-identifier trick.

## URL Validation

Add new URL validation techniques through:

- `UrlValidationAttackSetting`
- `UrlValidationContext`
- `UrlValidationPayloadGenerator`
- bundled payload resources when needed

Document:

- the payload family
- the category
- what parser or validation weakness it is meant to probe

## IDOR / BOLA

Add new IDOR techniques as `IdorPlaybook` implementations under `src/main/java/com/bypassfuzzer/burp/core/idor/playbooks/`.

Typical steps:

1. Create a new class implementing `IdorPlaybook`.
2. Give it:
   - a stable ID
   - a display name
   - a short description
   - `buildVariants(...)` logic
3. Register it in `IdorPlaybookRegistry`.
4. Add a section for it in `IDOR-BOLA-Playbooks`.

## IDOR Naming Guidance

Use IDs that tell us what family the playbook belongs to.

Good examples:

- `idor.path.suffix_formats`
- `idor.query.conflicting_identifiers`
- `idor.hybrid.identifier_encoding`

Avoid vague IDs that will become confusing later.

## Documentation Checklist

Whenever we add a playbook or attack family, capture:

- what problem it targets
- why we believe it is worth keeping in the product
- what exact mutations it performs
- what result pattern would make it interesting

## Suggested Future Convention

If the playbook count keeps growing, consider adding a small doc comment block in the code for each technique:

- `PLAYBOOK: <stable-id>`
- `WHY: <one-line rationale>`
- `NOTES: <any special scope or caveat>`

That will keep the code and wiki aligned.
