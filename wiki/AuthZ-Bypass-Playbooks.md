# AuthZ Bypass Playbooks

The `Bypass` tab is the main authorization-bypass testing area.

The registry lives in `src/main/java/com/bypassfuzzer/burp/core/attacks/AttackRegistry.java`.

This page is intentionally not a full payload dump. The goal is to explain why each attack family exists, show a few representative examples, and show the kind of broken target logic the family is trying to expose.

## Why These Are In The Tool

These playbooks are in the tool because access-control mistakes tend to cluster around a few boundaries:

- reverse proxies and trusted headers
- path normalization and routing mismatches
- method-based authorization differences
- parser differences between body formats and encodings
- hidden debug toggles and alternate request sources

The point of the bypass tab is to turn those families into repeatable, curated tests instead of making the tester hand-build each variation from scratch.

## `header` - Header

### Purpose

Header payloads exist because some applications and reverse proxies trust client-supplied routing, forwarding, or identity headers more than they should.

This family is trying to catch cases where:

- the edge denies a request but the backend trusts a rewrite header
- a backend treats a request as internal because of a spoofed forwarding header
- a route is selected from a header rather than the actual path

### Representative Examples

```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

Some payloads also combine a header override with a path swap, such as sending `/` on the request line while placing the protected path in a rewrite-style header.

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

## `path` - Path

### Purpose

Path normalization payloads aim to find cases where the security layer and the routing layer disagree about what path is actually being requested.

This family is trying to catch cases where:

- auth checks inspect the raw path
- routing uses a normalized path
- one layer collapses separators or dot segments and another does not

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

If `request.path()` and `normalizePath(request.path())` do not behave the same way, the auth check and the route handler can end up protecting different paths.

## `verb` - Verb

### Purpose

Verb payloads exist because some endpoints apply authorization checks to one HTTP method and forget to apply the same logic to the others.

This family is trying to catch cases where:

- `GET` is protected but `HEAD` is not
- read routes are protected differently from update or delete routes
- method override headers trigger a different code path

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

## `param` - Debug Params

### Purpose

Debug parameter payloads aim to surface routes that become less protected when a query parameter looks like a feature flag, debug toggle, or internal-mode switch.

This family is trying to catch cases where:

- debug parameters enable internal behavior
- feature flags disable normal checks
- existing parameters accept truthy or special values that weaken enforcement

### Representative Examples

```http
?debug=true
?admin=true
?preview=1
?internal=yes
?access=off
```

The attack also fuzzes existing query parameters with values such as:

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

## `cookie` - Debug Cookies

### Purpose

Debug cookie payloads aim to find the same class of issue as debug params, but in cookie-backed toggles and state flags.

This family is trying to catch cases where:

- an internal mode is enabled by a cookie
- support or staging behavior is controlled by a cookie
- existing cookie values can be fuzzed into a privileged state

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

## `trailingdot` - Trailing Dot

### Purpose

Trailing-dot payloads aim to catch host or route handling that treats fully-qualified dotted forms differently from normal forms.

This family is trying to catch cases where:

- one layer strips the trailing dot
- another layer compares the dotted host literally
- host-based access rules are inconsistent

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

## `trailingslash` - Trailing Slash

### Purpose

Trailing-slash payloads aim to detect route handling differences where `/admin` and `/admin/` do not travel through the same authorization logic.

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

## `extension` - Extension

### Purpose

Extension payloads aim to find stacks that route or authorize file-like paths differently from directory-like paths.

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

## `contenttype` - Content-Type

### Purpose

Content-Type payloads aim to detect cases where the application handles the same logical parameters differently depending on whether they arrive as form data, JSON, XML, or multipart.

This family is trying to catch cases where:

- one parser populates fields that another parser ignores
- middleware validates one body type but the app accepts another
- an auth-sensitive field moves to a parser path with weaker checks

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

## `encoding` - Encoding

### Purpose

Encoding payloads aim to catch cases where different layers decode paths, names, or values at different times or a different number of times.

This family is trying to catch cases where:

- the filter examines raw bytes
- the router decodes once
- the application decodes twice

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

## `protocol` - Protocol

### Purpose

Protocol payloads aim to find older or alternate HTTP parsing paths that enforce authorization differently.

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

## `case` - Case Variation

### Purpose

Case-variation payloads aim to find route or parser mismatches where one layer compares case-sensitively and another normalizes case.

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
- The payload examples above are representative, not exhaustive.
- The actual emitted payloads come from a combination of curated wordlists, generated variants, and request-aware rewrites.
- Not every bypass attack belongs in every future testing area. The IDOR tab should only reuse the bypass ideas that make sense for object-level authorization testing.
