package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CoverageSweepEngineTest {

    @Test
    void authenticatedDiscoveryIsPassiveAndInventoriesIdentifiers() {
        HttpRequest get = requestWithHeaders("/account", "", "GET", Map.of(
            "Authorization", "Bearer secret",
            "Cookie", "theme=dark; JSESSIONID=secret"
        ), "");
        HttpRequest post = requestWithHeaders("/account", "", "POST", Map.of("X-Api-Key", "secret"), "");
        List<ProxyHttpRequestResponse> history = List.of(history(get, 200, 2), history(post, 204, 1));
        AtomicInteger sends = new AtomicInteger();
        RequestSender sender = new RequestSender() {
            public HttpResponse send(HttpRequest request) { sends.incrementAndGet(); return response(200, "text/plain", "ok"); }
            public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) { return send(request); }
        };
        CoverageSweepOptions options = CoverageSweepOptions.defaults().withAuthenticatedTraffic(
            CoverageSweepAuthSelection.defaults());

        CoverageSweepPreview preview = new CoverageSweepEngine(api(history), sender, new CoverageSweepProbeGenerator())
            .collectPreview(options);

        assertEquals(2, preview.candidates().size());
        assertTrue(preview.discoveredHeaderNames().contains("Authorization"));
        assertTrue(preview.discoveredHeaderNames().contains("X-Api-Key"));
        assertEquals(Set.of("theme", "JSESSIONID"), preview.discoveredCookieNames());
        assertEquals(0, sends.get());
    }

    @Test
    void authenticatedDiscoveryExcludesStaticAssetsByDefaultAndCanIncludeThem() {
        HttpRequest account = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest script = requestWithHeaders("/assets/app.js?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest image = requestWithHeaders("/avatar", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest stylesheet = requestWithHeaders("/assets/site.css?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest font = requestWithHeaders("/assets/inter.woff2", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        List<ProxyHttpRequestResponse> history = List.of(
            history(account, 200, 5, "application/json"),
            history(script, 200, 4, "text/plain"),
            history(image, 200, 3, "image/png"),
            history(stylesheet, 200, 2, "text/plain"),
            history(font, 200, 1, "application/octet-stream")
        );
        CoverageSweepEngine engine = new CoverageSweepEngine(api(history),
            new StaticSender(response(200, "text/plain", "ok")), new CoverageSweepProbeGenerator());
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults().withAuthenticatedTraffic(
            CoverageSweepAuthSelection.defaults());

        CoverageSweepPreview filtered = engine.collectPreview(defaults);

        assertEquals(List.of("/account"), filtered.candidates().stream()
            .map(CoverageSweepCandidate::path).toList());

        CoverageSweepOptions includingStatic = new CoverageSweepOptions(
            defaults.statuses(),
            defaults.inScopeOnly(),
            defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(),
            defaults.concurrency(),
            defaults.requestsPerSecond(),
            defaults.requestDelayMs(),
            defaults.throttleStatusCodes(),
            defaults.mode(),
            defaults.authSelection(),
            false
        );

        assertEquals(5, engine.collectPreview(includingStatic).candidates().size());
    }

    @Test
    void selectedCookieIdentifiesCandidateButAttacksRemoveEntireCookieAndAuthHeaders() {
        HttpRequest original = requestWithHeaders("/account", "", "GET", Map.of(
            "Cookie", "theme=dark; JSESSIONID=secret",
            "Authorization", "Bearer secret",
            "Proxy-Authorization", "Basic secret",
            "X-Api-Key", "secret",
            "X-Keep", "value"
        ), "");
        CoverageSweepAuthSelection selection = new CoverageSweepAuthSelection(
            Set.of("Authorization", "X-Api-Key"), Set.of("JSESSIONID"), false);
        CoverageSweepOptions options = CoverageSweepOptions.defaults().withAuthenticatedTraffic(selection);
        CoverageSweepCandidate candidate = candidate(original, 200);
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "text/plain", "ok")), new CoverageSweepProbeGenerator());

        assertTrue(engine.matchesAuthSelection(candidate, selection));
        List<CoverageSweepProbe> probes = engine.buildProbes(candidate, options);

        assertTrue(probes.size() > 100 && probes.size() <= options.maxProbesPerCandidate());
        assertTrue(probes.stream().noneMatch(probe -> "Control".equals(probe.family())));
        HttpRequest first = probes.get(0).request();
        assertFalse(first.hasHeader("Cookie"));
        assertFalse(first.hasHeader("Authorization"));
        assertFalse(first.hasHeader("Proxy-Authorization"));
        assertFalse(first.hasHeader("X-Api-Key"));
        assertEquals("value", first.headerValue("X-Keep"));
        assertEquals("theme=dark; JSESSIONID=secret", original.headerValue("Cookie"));
    }

    @Test
    void authenticatedExecutionLeavesSignalBlankAndCarriesHistoryResponse() throws Exception {
        HttpResponse originalResponse = response(200, "application/json", "authenticated");
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest, originalResponse, "key",
            originalRequest.url(), "GET", "example.com", "/account", 200, 13,
            "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 2, 1, 0, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false));
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new StaticSender(response(200, "application/json", "probe")), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(result -> result.getPayloadEncoding().isBlank()));
        assertTrue(results.stream().allMatch(result -> result.getOriginalRequest() == originalRequest));
        assertTrue(results.stream().allMatch(result -> result.getOriginalResponse() == originalResponse));
        assertTrue(results.stream().noneMatch(result -> "Control".equals(result.getPayloadFamily())));
    }

    @Test
    void authenticatedExecutionVerifiesAnonymousControlAndLabelsLikelyPublic() throws Exception {
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpResponse originalResponse = response(200, "application/json", "authenticated");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest, originalResponse, "key",
            originalRequest.url(), "GET", "example.com", "/account", 200, 13,
            "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 1, 1, 0, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false), true, true);
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new SequenceSender(List.of(
                response(200, "application/json", "public"),
                response(403, "application/json", "blocked")
            )), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertEquals("Unauthenticated Control", results.get(0).getPayloadFamily());
        assertEquals("LIKELY PUBLIC: authenticated 200 -> unauthenticated 200",
            results.get(0).getPayloadEncoding());
        assertFalse(results.get(0).getRequest().hasHeader("Authorization"));
        assertEquals("", results.get(1).getPayloadEncoding());
    }

    @Test
    void authenticatedMutationUsesAnonymousControlAsBypassBaseline() throws Exception {
        HttpRequest originalRequest = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(originalRequest,
            response(200, "application/json", "authenticated"), "key", originalRequest.url(), "GET",
            "example.com", "/account", 200, 13, "application/json", ZonedDateTime.now());
        CoverageSweepOptions options = new CoverageSweepOptions(Set.of(), true, 100, 1, 1, 0, 0,
            Set.of(429), CoverageSweepMode.AUTHENTICATED_TRAFFIC,
            new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false), true, true);
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()),
            new SequenceSender(List.of(
                response(403, "application/json", "blocked"),
                response(200, "application/json", "secret")
            )), new CoverageSweepProbeGenerator());

        assertTrue(engine.start(List.of(candidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertEquals("", results.get(0).getPayloadEncoding());
        assertEquals("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200", results.get(1).getPayloadEncoding());
    }

    @Test
    void classifiesThreeResponseAuthenticatedBypassWithWeakBoundaryMarker() {
        CoverageSweepCandidate candidate = candidate(request("/account", "", "GET", null, ""), 200);

        assertEquals("BYPASS?: authenticated 200 -> anonymous 302 -> probe 200",
            CoverageSweepClassifier.authenticatedBypassSignal(
                candidate,
                response(302, "text/html", "login"),
                response(200, "application/json", "secret")));
        assertEquals("BYPASS? (weak): authenticated 200 -> anonymous 404 -> probe 200",
            CoverageSweepClassifier.authenticatedBypassSignal(
                candidate,
                response(404, "application/json", "missing"),
                response(200, "application/json", "secret")));
        assertEquals("", CoverageSweepClassifier.authenticatedBypassSignal(
            candidate,
            response(403, "application/json", "blocked"),
            response(302, "text/html", "redirect")));
        assertEquals("", CoverageSweepClassifier.unauthenticatedMutationSignal(
            response(403, "application/json", "blocked"),
            response(302, "text/html", "redirect")));
    }

    @Test
    void importedExecutionCarriesOriginalRequestAndLiveControlResponse() throws Exception {
        HttpRequest originalRequest = request("/imported", "", "GET", null, "");
        HttpResponse controlResponse = response(403, "text/plain", "blocked");
        CoverageSweepCandidate importedCandidate = new CoverageSweepCandidate(
            originalRequest,
            null,
            "imported-key",
            originalRequest.url(),
            originalRequest.method(),
            "example.com",
            originalRequest.path(),
            0,
            0,
            "",
            ZonedDateTime.now()
        );
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                controlResponse,
                response(200, "application/json", "probe")
            )),
            new CoverageSweepProbeGenerator()
        );
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            2,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );
        List<AttackResult> results = new ArrayList<>();

        assertTrue(engine.start(List.of(importedCandidate), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(result -> result.getOriginalRequest() == originalRequest));
        assertTrue(results.stream().allMatch(result -> result.getOriginalResponse() == controlResponse));
    }

    @Test
    void collectsOnlyInScopeBlockedProxyHistoryWithResponses() {
        MontoyaApi api = api(
            List.of(
                history("/blocked", 403, true, 3),
                history("/unauth", 401, true, 2),
                history("/ok", 200, true, 1),
                history("/out", 403, false, 4),
                historyWithoutResponse("/empty", true, 5)
            )
        );

        CoverageSweepPreview preview = new CoverageSweepEngine(api, new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(CoverageSweepOptions.defaults());

        assertEquals(2, preview.blockedHistoryCount());
        assertEquals(2, preview.dedupedEndpointCount());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/blocked")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/unauth")));
    }

    @Test
    void collectsConfiguredRedirectAndClientErrorStatuses() {
        MontoyaApi api = api(List.of(
            history("/redirect", 302, true, 1),
            history("/blocked", 403, true, 2),
            history("/missing", 404, true, 3),
            history("/ok", 200, true, 4)
        ));
        CoverageSweepOptions options = new CoverageSweepOptions(
            java.util.Set.of(302, 401, 403, 404),
            true,
            100,
            25,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        CoverageSweepPreview preview = new CoverageSweepEngine(api, new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(options);

        assertEquals(3, preview.blockedHistoryCount());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/redirect")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/missing")));
    }

    @Test
    void dedupesEndpointShapesPreferringMostRecentAndCapsPreview() {
        List<ProxyHttpRequestResponse> history = new ArrayList<>();
        history.add(history("/users/1?id=1&debug=true", 403, true, 1));
        history.add(history("/users/2?debug=false&id=2", 401, true, 300));
        history.add(history("/reports/1", 403, true, 2));

        for (int i = 0; i < 130; i++) {
            history.add(history("/cap/item-" + i, 403, true, 10 + i));
        }

        CoverageSweepPreview preview = new CoverageSweepEngine(api(history), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .collectPreview(CoverageSweepOptions.defaults());

        assertEquals(132, preview.dedupedEndpointCount());
        assertEquals(100, preview.candidates().size());
        assertTrue(preview.candidates().stream().noneMatch(candidate -> candidate.path().equals("/users/1?id=1&debug=true")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().equals("/users/2?debug=false&id=2")));
    }

    @Test
    void importsTargetUrlsFromLinesAndDedupesEndpointShapes() {
        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromUrls(List.of(
                "https://victim.example/admin/users/1?debug=true&id=1",
                "https://victim.example/admin/users/2?id=2&debug=false",
                "https://victim.example/admin/info",
                "# comment",
                "not-a-url"
            ), CoverageSweepOptions.defaults());

        assertEquals(3, preview.blockedHistoryCount());
        assertEquals(2, preview.dedupedEndpointCount());
        assertEquals(2, preview.candidates().size());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.displayUrl().equals("https://victim.example/admin/info")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.path().startsWith("/admin/users/")));
        assertTrue(preview.candidates().stream().allMatch(candidate -> "GET".equals(candidate.method())));
    }

    @Test
    void importedTargetPreviewHonorsCandidateCap() {
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < 150; i++) {
            urls.add("https://victim.example/endpoint-" + i);
        }

        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromUrls(urls, CoverageSweepOptions.defaults());

        assertEquals(150, preview.blockedHistoryCount());
        assertEquals(150, preview.dedupedEndpointCount());
        assertEquals(100, preview.candidates().size());
    }

    @Test
    void importsOpenApiOperationsAsMethodAwareCandidates() {
        String spec = """
            openapi: 3.0.0
            servers:
              - url: https://api.example.test
            paths:
              /admin/{id}:
                get:
                  parameters:
                    - name: id
                      in: path
                      required: true
                      example: 7
                delete:
                  parameters:
                    - name: id
                      in: path
                      required: true
                      example: 7
            """;

        CoverageSweepPreview preview = importedEngine()
            .collectPreviewFromOpenApi(spec, "openapi.yaml", CoverageSweepOptions.defaults());

        assertEquals(2, preview.blockedHistoryCount());
        assertEquals(2, preview.candidates().size());
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.method().equals("GET")));
        assertTrue(preview.candidates().stream().anyMatch(candidate -> candidate.method().equals("DELETE")));
        assertTrue(preview.candidates().stream().allMatch(candidate -> candidate.path().equals("/admin/7")));
    }

    @Test
    void generatesBoundedHighSignalProbes() {
        CoverageSweepCandidate candidate = candidate(request("/admin/users", "", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertEquals(162, probes.size());
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.html")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;.xml")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users;")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users%3b.html")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users.json;")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?role=admin")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?.json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?format=json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?_format=json")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?api-version=1")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("//admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("///admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin//users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin///users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users/..")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%2e/admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/./admin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%2fadmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/ADMIN/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/USERS")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/Admin/Users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/AdMiN/uSeRs")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/%61dmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/adm%69n/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/%2561dmin/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/admin%2fusers")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Encoding")
            && probe.request().path().equals("/%61%64%6d%69%6e/users")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users/")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?debug=true")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?admin=true")));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().path().contains("jsessionid")));
        assertTrue(probes.stream().allMatch(probe -> "GET".equals(probe.request().method())));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Original-URL")));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Rewrite-URL")));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Content-Type")
            && "application/json".equals(probe.request().headerValue("Content-Type"))));
        assertTrue(probes.stream().anyMatch(probe -> probe.family().equals("Content-Type")
            && "application/x-www-form-urlencoded".equals(probe.request().headerValue("Content-Type"))));
        assertTrue(probes.stream().anyMatch(probe -> "Bearer A".equals(probe.request().headerValue("Authorization"))));
        assertTrue(probes.stream().anyMatch(probe -> "Basic A".equals(probe.request().headerValue("Authorization"))));
        assertFalse(probes.stream().anyMatch(probe -> probe.request().hasHeader("X-Custom-IP-Authorization")));
    }

    @Test
    void sweepIteratesStandaloneSemicolonSegmentsAcrossPathBoundaries() {
        CoverageSweepCandidate candidate = candidate(request("/api/v2/admin/users/profile", "mode=full", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/;/v2/;/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/;/admin/;/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/admin/;/users/;/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/;/api/;/v2/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/v2/admin/users/;/profile/;?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%3b/v2/%3b/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/./v2/./admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%2e/v2/%2e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%252e/v2/%252e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%u002e/v2/%u002e/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%253b/v2/%253b/admin/users/profile?mode=full")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/api/%u003b/v2/%u003b/admin/users/profile?mode=full")));
    }

    @Test
    void appendsDebugParamsAfterExistingQueryString() {
        CoverageSweepCandidate candidate = candidate(request("/admin/users", "page=1", "GET", null, ""), 403);
        List<CoverageSweepProbe> probes = new CoverageSweepEngine(api(List.of()), new StaticSender(response(403, "text/plain", "blocked")), new CoverageSweepProbeGenerator())
            .buildProbes(candidate, CoverageSweepOptions.defaults());

        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?page=1&debug=true")));
        assertTrue(probes.stream().anyMatch(probe -> probe.request().path().equals("/admin/users?page=1&admin=true")));
    }

    @Test
    void classifiesBypassAndUnchangedBlockedResponse() {
        CoverageSweepCandidate candidate = candidate(request("/something", "", "GET", null, ""), 403);

        assertTrue(CoverageSweepClassifier.isInteresting(
            candidate,
            response(403, "text/plain", "blocked"),
            response(200, "application/json", "secret data")
        ));
        assertEquals("403 -> 200", CoverageSweepClassifier.signal(
            candidate,
            response(403, "text/plain", "blocked"),
            response(200, "application/json", "secret data")
        ));

        assertFalse(CoverageSweepClassifier.isInteresting(
            candidate,
            response(403, "text/plain", "blocked"),
            response(403, "text/plain", "blocked")
        ));
        assertEquals("", CoverageSweepClassifier.signal(
            candidate,
            response(403, "text/plain", "blocked"),
            response(403, "text/plain", "blocked")
        ));
    }

    @Test
    void doesNotSignalClientErrorResponsesEvenWithLargeBodyDelta() {
        CoverageSweepCandidate candidate = candidate(request("/redirect", "", "GET", null, ""), 302);

        assertFalse(CoverageSweepClassifier.isInteresting(
            candidate,
            response(302, "text/html", ""),
            response(404, "text/html", "x".repeat(500))
        ));
        assertEquals("", CoverageSweepClassifier.signal(
            candidate,
            response(302, "text/html", ""),
            response(404, "text/html", "x".repeat(500))
        ));
    }

    @Test
    void executionLabelsLikelyBypassResults() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new SequenceSender(List.of(
                response(403, "text/plain", "blocked"),
                response(200, "application/json", "secret")
            )),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            2,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/something", "", "GET", null, ""), 403)), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) {
            Thread.sleep(20);
        }

        assertEquals(2, results.size());
        assertEquals("403 -> 200", results.get(1).getPayloadEncoding());
    }

    @Test
    void executionLabelsMissingTransportResponsesExplicitly() throws Exception {
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            new StaticSender(null),
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = new ArrayList<>();
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            1,
            1,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(candidate(request("/something", "", "GET", null, ""), 403)),
            options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) Thread.sleep(20);

        assertEquals(1, results.size());
        assertEquals("No response", results.get(0).getPayloadEncoding());
        assertEquals(0, results.get(0).getStatusCode());
    }

    @Test
    void executesCandidatesConcurrentlyWhenConfigured() throws Exception {
        ConcurrentTrackingSender sender = new ConcurrentTrackingSender(response(403, "text/plain", "blocked"), 120);
        CoverageSweepEngine engine = new CoverageSweepEngine(
            api(List.of()),
            sender,
            new CoverageSweepProbeGenerator()
        );
        List<AttackResult> results = Collections.synchronizedList(new ArrayList<>());
        CoverageSweepOptions options = new CoverageSweepOptions(
            CoverageSweepOptions.defaults().statuses(),
            true,
            100,
            1,
            2,
            0,
            CoverageSweepOptions.defaults().throttleStatusCodes()
        );

        assertTrue(engine.start(List.of(
            candidate(request("/one", "", "GET", null, ""), 403),
            candidate(request("/two", "", "GET", null, ""), 403)
        ), options, results::add, () -> { }));
        for (int i = 0; i < 50 && engine.isRunning(); i++) {
            Thread.sleep(20);
        }

        assertEquals(2, results.size());
        assertTrue(sender.maxActive.get() > 1);
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history) {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(any())).thenAnswer(invocation -> !invocation.getArgument(0, String.class).contains("/out"));
        when(api.proxy().history(any())).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return history.stream().filter(filter::matches).toList();
        });
        return api;
    }

    private CoverageSweepEngine importedEngine() {
        return new CoverageSweepEngine(
            api(List.of()),
            new StaticSender(response(403, "text/plain", "blocked")),
            new CoverageSweepProbeGenerator(),
            uri -> request(
                uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath(),
                uri.getRawQuery() == null ? "" : uri.getRawQuery(),
                "GET",
                null,
                ""
            )
        );
    }

    private ProxyHttpRequestResponse history(String path, int status, boolean inScope, int minutes) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpRequest request = request(path, "", "GET", null, "");
        return history(item, request, status, minutes);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, int minutes) {
        return history(mock(ProxyHttpRequestResponse.class), request, status, minutes);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, int minutes, String contentType) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpResponse response = response(status, contentType, "body");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now().plusMinutes(minutes));
        return item;
    }

    private ProxyHttpRequestResponse history(ProxyHttpRequestResponse item, HttpRequest request, int status, int minutes) {
        HttpResponse response = response(status, "text/plain", "blocked");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now().plusMinutes(minutes));
        if (request.path().equals("/out")) {
            when(item.request()).thenReturn(request("/out", "", "GET", null, ""));
            when(item.finalRequest()).thenReturn(request("/out", "", "GET", null, ""));
        }
        return item;
    }

    private ProxyHttpRequestResponse historyWithoutResponse(String path, boolean inScope, int minutes) {
        ProxyHttpRequestResponse item = history(path, 403, inScope, minutes);
        when(item.hasResponse()).thenReturn(false);
        when(item.response()).thenReturn(null);
        return item;
    }

    private CoverageSweepCandidate candidate(HttpRequest request, int status) {
        HttpResponse response = response(status, "text/plain", "blocked");
        return new CoverageSweepCandidate(
            request,
            response,
            "key",
            request.url(),
            request.method(),
            "example.com",
            request.path(),
            status,
            response.body().length(),
            "text/plain",
            ZonedDateTime.now()
        );
    }

    private HttpResponse response(int status, String contentType, String body) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray bodyBytes = byteArray(body == null ? 0 : body.length());
        List<HttpHeader> headers = List.of(header("Content-Type", contentType));
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(bodyBytes);
        when(response.headers()).thenReturn(headers);
        return response;
    }

    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }

    private ByteArray byteArray(int length) {
        ByteArray byteArray = mock(ByteArray.class);
        when(byteArray.length()).thenReturn(length);
        return byteArray;
    }

    private record StaticSender(HttpResponse response) implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return response;
        }
    }

    private static final class SequenceSender implements RequestSender {
        private final List<HttpResponse> responses;
        private int index = 0;

        private SequenceSender(List<HttpResponse> responses) {
            this.responses = responses;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            HttpResponse response = responses.get(Math.min(index, responses.size() - 1));
            index++;
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }

    private static final class ConcurrentTrackingSender implements RequestSender {
        private final HttpResponse response;
        private final long delayMs;
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maxActive = new AtomicInteger();

        private ConcurrentTrackingSender(HttpResponse response, long delayMs) {
            this.response = response;
            this.delayMs = delayMs;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            int current = active.incrementAndGet();
            maxActive.accumulateAndGet(current, Math::max);
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                active.decrementAndGet();
            }
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }
}
