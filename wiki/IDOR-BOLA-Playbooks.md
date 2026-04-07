# IDOR / BOLA Playbooks

The `IDOR` tab is for object-identifier manipulation and broken object-level authorization testing.

The registry lives in `src/main/java/com/bypassfuzzer/burp/core/idor/playbooks/IdorPlaybookRegistry.java`.

## Why This Is In The Tool

An IDOR/BOLA workflow is different from a generic AuthZ bypass workflow.

The tester usually has:

- one identifier they are allowed to access
- one identifier they are not allowed to access

The job of the tab is to:

1. establish a control request with the authorized identifier
2. establish a denied baseline with the target identifier
3. run named object-manipulation playbooks against the target identifier

This lets the results answer a more specific question:

"What request mutations make identifier 2 behave more like identifier 1?"

## Naming Scheme

- `idor.path.*`
  Path and route-shape manipulation around the target identifier.
- `idor.query.*`
  Query-string conflicts and duplicate identifier source tests.
- `idor.hybrid.*`
  Curated ideas borrowed from the bypass tab when they are also useful for IDOR.

## Current Playbooks

### `idor.path.suffix_formats`

Display name:
`Suffix Formats`

Why it exists:
Some routes or middleware treat file-like or version-suffixed paths differently.

What it does:

- adds `.json` and `.html` to the target identifier
- adds `.json` to the terminal version segment
- combines both forms

### `idor.path.trailing_slash`

Display name:
`Trailing Slash`

Why it exists:
Authorization and routing layers often disagree on whether a terminal slash matters.

What it does:

- removes the slash if the path ends with one
- adds the slash if the path does not end with one

### `idor.path.special_identifier_values`

Display name:
`Special Identifier Values`

Why it exists:
Some applications have sentinel handling for values such as `0`, `1`, `-1`, or encoded characters.

What it does:

- swaps the target identifier for `0`
- swaps the target identifier for `1`
- swaps the target identifier for `-1`
- swaps the target identifier for `%C3%87`

### `idor.query.conflicting_identifiers`

Display name:
`Conflicting Query Identifiers`

Why it exists:
Some applications resolve the object from the path, some from the query string, and some take the first or last match.

What it does:

- adds `childId=<authorized>`
- adds `id=<authorized>`
- adds conflicting query hints where one parameter points at the authorized identifier and another points at the target identifier

### `idor.hybrid.identifier_encoding`

Display name:
`Identifier Encoding`

Why it exists:
Sometimes the router, validator, and auth layer decode the identifier differently.

What it does:

- full URL-encodes the target identifier
- double-URL-encodes the target identifier
- partially encodes the leading character
- partially encodes a middle character

### `idor.hybrid.method_override`

Display name:
`Method Override`

Why it exists:
Object-level auth issues often show up on update or delete paths even when the read path is denied.

What it does:

- tries direct CRUD-relevant methods such as `HEAD`, `POST`, `PUT`, `PATCH`, and `DELETE`
- adds curated override headers such as `X-HTTP-Method-Override`
- combines `POST` with method-override headers

## Notes For Future Additions

When adding new playbooks, prefer grouping them into one of the existing namespaces:

- `idor.path.*`
- `idor.query.*`
- `idor.body.*`
- `idor.header.*`
- `idor.hybrid.*`

The point is to keep the code and the docs readable when the playbook count grows.
