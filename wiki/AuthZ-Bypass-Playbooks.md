# AuthZ Bypass Playbooks

The `Bypass` tab is the main authorization-bypass testing area.

The registry lives in `src/main/java/com/bypassfuzzer/burp/core/attacks/AttackRegistry.java`.

This page is meant to read like an operator guide, not a payload dump. It explains why each attack family exists, shows a few representative examples, and shows the kind of broken target logic the family is trying to expose.

## Why This Is In The Tool

Access-control bugs tend to cluster around a few boundaries:

- proxies and trusted forwarding headers
- path normalization and routing mismatches
- method-specific authorization gaps
- parser differences between body formats and encodings
- hidden debug toggles and alternate request sources

The point of the `Bypass` tab is to turn those families into repeatable, curated tests instead of making the tester hand-build each variation from scratch.

## Current Playbooks

### `header` - Header

### Purpose

This family exists because some applications and reverse proxies trust client-supplied routing, forwarding, or identity headers more than they should.

### Representative Examples

```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

Some payloads also combine a rewrite header with a harmless-looking request line, such as sending `/` on the request line while placing the protected path in a rewrite-style header.

### What The Broken Target Code Might Look Like

```java
String effectivePath = request.header("X-Original-URL");
if (effectivePath == null) {
    effectivePath = request.path();
}

if (effectivePath.startsWith("/admin")) {
    return adminHandler(request);
}
```

```java
String clientIp = request.header("X-Forwarded-For");
if ("127.0.0.1".equals(clientIp)) {
    allowInternalOnlyRoute();
}
```

### `path` - Path

### Purpose

This family exists because the security layer and the routing layer do not always agree about what path is actually being requested.

### Representative Examples

```http
/admin/../admin
/admin//
/./admin/
/%2e/admin
/admin;%2f
```

The exact set comes from curated path payload resources and generated variants rather than one hardcoded list in the docs.

### What The Broken Target Code Might Look Like

```java
if (request.path().startsWith("/admin")) {
    denyUnlessAdmin();
}

String normalized = normalizePath(request.path());
route(normalized);
```

### `verb` - Verb

### Purpose

This family exists because some endpoints apply authorization checks to one HTTP method and forget to apply the same logic to the others.

### Representative Examples

```http
HEAD /admin/report HTTP/1.1
POST /admin/report HTTP/1.1
PATCH /admin/report HTTP/1.1
DELETE /admin/report HTTP/1.1
X-HTTP-Method-Override: GET
```

### What The Broken Target Code Might Look Like

```java
if ("GET".equals(request.method()) && request.path().startsWith("/admin")) {
    requireAdmin(request);
}

handleRequest(request);
```

### `param` - Debug Params

### Purpose

This family exists because some routes become less protected when a query parameter looks like a feature flag, debug toggle, or internal-mode switch.

### Representative Examples

```http
?debug=true
?admin=true
?preview=1
?internal=yes
?access=off
```

Existing parameters are also fuzzed with values such as:

```text
true, 1, yes, on, admin, root, false, 0, no, off
```

### What The Broken Target Code Might Look Like

```java
boolean debug = "true".equals(request.query("debug"));
if (debug) {
    return renderWithoutAuthChecks(request);
}
```

```java
if ("admin".equals(request.query("mode"))) {
    skipAccessControl = true;
}
```

### `cookie` - Debug Cookies

### Purpose

This family exists because the same class of issue can hide in cookie-backed toggles and state flags instead of query parameters.

### Representative Examples

```http
Cookie: debug=true
Cookie: admin=yes
Cookie: preview=1
Cookie: role=root
```

### What The Broken Target Code Might Look Like

```java
if ("1".equals(request.cookie("preview"))) {
    bypassAuthorization();
}
```

### `trailingdot` - Trailing Dot

### Purpose

This family exists because host or route handling sometimes treats fully-qualified dotted forms differently from normal forms.

### Representative Examples

```http
Host: admin.internal.
/admin.
```

### What The Broken Target Code Might Look Like

```java
if ("admin.internal".equals(request.host())) {
    requireAdmin();
}

proxyToUpstream(stripTrailingDot(request.host()));
```

### `trailingslash` - Trailing Slash

### Purpose

This family exists because `/admin` and `/admin/` do not always pass through the same normalization or authorization logic.

### Representative Examples

```http
/admin
/admin/
```

### What The Broken Target Code Might Look Like

```java
if ("/admin".equals(request.path())) {
    requireAdmin();
}

route(normalizeSlash(request.path()));
```

### `extension` - Extension

### Purpose

This family exists because some stacks route or authorize file-like paths differently from directory-like or API-style paths.

### Representative Examples

```http
/admin.json
/admin.html
/admin.php
```

### What The Broken Target Code Might Look Like

```java
if (request.path().equals("/admin")) {
    requireAdmin();
}

staticOrApiRouter.handle(request.path());
```

### `contenttype` - Content-Type

### Purpose

This family exists because the same logical parameters can be handled differently depending on whether they arrive as form data, JSON, XML, or multipart.

### Representative Examples

```http
Content-Type: application/x-www-form-urlencoded
role=admin&debug=true
```

```http
Content-Type: application/json
{"role":"admin","debug":true}
```

```http
Content-Type: application/xml
<root><role>admin</role><debug>true</debug></root>
```

### What The Broken Target Code Might Look Like

```java
if (request.contentType().equals("application/x-www-form-urlencoded")) {
    validateStrictly(request.formParams());
}

Object body = parseAnyBody(request);
handle(body);
```

### `encoding` - Encoding

### Purpose

This family exists because different layers decode paths, names, or values at different times or a different number of times.

### Representative Examples

```http
/admin%2fpanel
/admin%252fpanel
?role%5B0%5D=admin
?debug=%2574rue
```

### What The Broken Target Code Might Look Like

```java
if (request.rawPath().contains("/admin/")) {
    deny();
}

String decodedPath = urlDecode(request.rawPath());
route(decodedPath);
```

### `protocol` - Protocol

### Purpose

This family exists because older or alternate HTTP parsing paths do not always enforce authorization the same way as the main middleware chain.

### Representative Examples

```http
GET /admin HTTP/1.0
GET /admin HTTP/0.9
```

### What The Broken Target Code Might Look Like

```java
if ("HTTP/1.1".equals(request.protocol())) {
    applyFullMiddlewareChain(request);
} else {
    passThroughLegacyHandler(request);
}
```

### `case` - Case Variation

### Purpose

This family exists because one layer may compare case-sensitively while another normalizes case before routing or parsing.

### Representative Examples

```http
/Admin
/aDmIn
X-OrIgInAl-UrL: /AdMiN
```

### What The Broken Target Code Might Look Like

```java
if (request.path().startsWith("/admin")) {
    requireAdmin();
}

route(request.path().toLowerCase());
```

## Notes

- The attack framework is centralized through `AttackExecutionSupport` and `AttackExecutor`.
- The examples above are representative, not exhaustive.
- The actual emitted payloads come from a combination of curated wordlists, generated variants, and request-aware rewrites.
- Not every bypass attack belongs in every future testing area. The IDOR tab should only reuse the bypass ideas that make sense for object-level authorization testing.
