package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestPathUtils;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.CookieHeaderUtils;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class CoverageSweepEngine {

    private static final Pattern IMAGE_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:apng|avif|bmp|gif|ico|jpe?g|png|svg|tiff?|webp)$");
    private static final Pattern JAVASCRIPT_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:cjs|js|mjs|js\\.map)$");
    private static final Pattern STYLESHEET_OR_FONT_PATH_PATTERN = Pattern.compile(
        ".*\\.(?:css|woff2?)$");

    private final MontoyaApi api;
    private final RequestSender requestSender;
    private final CoverageSweepProbeGenerator probeGenerator;
    private final FullBypassSweepProbeGenerator fullProbeGenerator;
    private final UrlRequestFactory urlRequestFactory;
    private final TargetUrlResolver targetUrlResolver = new TargetUrlResolver();

    private volatile boolean running = false;
    private Thread runnerThread;
    private ExecutorService executor;
    private RateLimiter rateLimiter;

    public CoverageSweepEngine(MontoyaApi api) {
        this(api, new MontoyaRequestSender(api, true), new CoverageSweepProbeGenerator());
    }

    CoverageSweepEngine(MontoyaApi api, RequestSender requestSender, CoverageSweepProbeGenerator probeGenerator) {
        this(api, requestSender, probeGenerator, CoverageSweepEngine::defaultImportedRequest);
    }

    CoverageSweepEngine(MontoyaApi api,
                        RequestSender requestSender,
                        CoverageSweepProbeGenerator probeGenerator,
                        UrlRequestFactory urlRequestFactory) {
        this.api = api;
        this.requestSender = requestSender;
        this.probeGenerator = probeGenerator;
        this.fullProbeGenerator = new FullBypassSweepProbeGenerator(api);
        this.urlRequestFactory = urlRequestFactory == null ? CoverageSweepEngine::defaultImportedRequest : urlRequestFactory;
    }

    public CoverageSweepPreview collectPreview(CoverageSweepOptions options) {
        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        history = history == null ? List.of() : history;
        int successfulResponseCount = effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC
            ? (int) history.stream().filter(this::hasSuccessfulResponse).count()
            : 0;
        int inScopeSuccessfulResponseCount = effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC
            ? (int) history.stream().filter(this::hasSuccessfulResponse)
                .filter(item -> !effectiveOptions.inScopeOnly() || isInScope(item)).count()
            : 0;
        List<ProxyHttpRequestResponse> matchingHistory = history.stream()
            .filter(item -> eligible(item, effectiveOptions))
            .toList();
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        Set<String> discoveredHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Set<String> discoveredCookies = new TreeSet<>();

        for (ProxyHttpRequestResponse item : matchingHistory) {
            CoverageSweepCandidate candidate = toCandidate(item);
            if (candidate == null) {
                continue;
            }

            CoverageSweepCandidate existing = deduped.get(candidate.dedupeKey());
            if (existing == null || newer(candidate.time(), existing.time())) {
                deduped.put(candidate.dedupeKey(), candidate);
            }
            if (effectiveOptions.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
                collectAuthIdentifiers(candidate.request(), discoveredHeaders, discoveredCookies);
            }
        }

        List<CoverageSweepCandidate> candidates = new ArrayList<>(deduped.values());
        candidates.sort(Comparator
            .comparing(CoverageSweepCandidate::time, Comparator.nullsLast(Comparator.reverseOrder()))
            .thenComparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        int cap = Math.max(1, effectiveOptions.maxCandidates());
        if (effectiveOptions.mode() == CoverageSweepMode.BLOCKED_RESPONSES && candidates.size() > cap) {
            candidates = new ArrayList<>(candidates.subList(0, cap));
        }

        return new CoverageSweepPreview(matchingHistory.size(), deduped.size(), List.copyOf(candidates),
            Set.copyOf(discoveredHeaders), Set.copyOf(discoveredCookies), history.size(),
            successfulResponseCount, inScopeSuccessfulResponseCount);
    }

    public CoverageSweepPreview collectPreviewFromUrls(List<String> urls, CoverageSweepOptions options) {
        return collectPreviewFromUrls(urls, options, true);
    }

    public CoverageSweepPreview collectPreviewFromUrls(List<String> urls, CoverageSweepOptions options,
                                                        boolean dedupeEndpoints) {
        if (urls == null || urls.isEmpty()) {
            return new CoverageSweepPreview(0, 0, List.of());
        }

        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> imported = new ArrayList<>();
        int parsedTargets = 0;

        for (String url : urls) {
            CoverageSweepCandidate candidate = toImportedCandidate(url);
            if (candidate == null) {
                continue;
            }
            parsedTargets++;
            deduped.putIfAbsent(candidate.dedupeKey(), candidate);
            imported.add(candidate);
        }

        List<CoverageSweepCandidate> candidates = dedupeEndpoints
            ? new ArrayList<>(deduped.values()) : imported;
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        return new CoverageSweepPreview(parsedTargets, deduped.size(), List.copyOf(candidates));
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, "", options);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, baseUrlOverride, "", options);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           String sourceUrl,
                                                           CoverageSweepOptions options) {
        return collectPreviewFromOpenApi(source, fileName, baseUrlOverride, sourceUrl, options, true);
    }

    public CoverageSweepPreview collectPreviewFromOpenApi(String source, String fileName,
                                                           String baseUrlOverride,
                                                           String sourceUrl,
                                                           CoverageSweepOptions options,
                                                           boolean dedupeEndpoints) {
        List<OpenApiOperation> operations = new OpenApiSpecParser().parse(
            source, fileName, baseUrlOverride, sourceUrl);
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        List<CoverageSweepCandidate> imported = new ArrayList<>();
        for (OpenApiOperation operation : operations) {
            CoverageSweepCandidate candidate = toImportedCandidate(operation);
            if (candidate != null) {
                deduped.putIfAbsent(candidate.dedupeKey(), candidate);
                imported.add(candidate);
            }
        }
        List<CoverageSweepCandidate> candidates = dedupeEndpoints
            ? new ArrayList<>(deduped.values()) : imported;
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo))
            .thenComparing(CoverageSweepCandidate::method));
        return new CoverageSweepPreview(operations.size(), deduped.size(), List.copyOf(candidates));
    }

    public List<CoverageSweepProbe> buildProbes(CoverageSweepCandidate candidate, CoverageSweepOptions options) {
        if (candidate == null) {
            return List.of();
        }
        CoverageSweepOptions effective = options == null ? CoverageSweepOptions.defaults() : options;
        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(effective.requestHeaders());
        if (effective.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            HttpRequest anonymousRequest = stripAuthentication(candidate.request(), effective.authSelection());
            return reconcileProbes(generateProbes(anonymousRequest, effective, false),
                anonymousRequest, headerPolicy);
        }
        return reconcileProbes(generateProbes(candidate.request(), effective, true),
            candidate.request(), headerPolicy);
    }

    private List<CoverageSweepProbe> generateProbes(HttpRequest request,
                                                     CoverageSweepOptions options,
                                                     boolean includeControl) {
        if (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS) {
            return fullProbeGenerator.buildProbes(request, includeControl);
        }
        return probeGenerator.buildProbes(request, options, includeControl);
    }

    public boolean start(List<CoverageSweepCandidate> candidates,
                         CoverageSweepOptions options,
                         Consumer<AttackResult> resultCallback,
                         Runnable completionCallback) {
        if (running || candidates == null || candidates.isEmpty()) {
            return false;
        }

        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        running = true;
        runnerThread = new Thread(() -> {
            try {
                execute(candidates, effectiveOptions, resultCallback);
            } finally {
                running = false;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-coverage-sweep");
        runnerThread.start();
        return true;
    }

    public void stop() {
        running = false;
        if (executor != null) {
            executor.shutdownNow();
        }
        if (runnerThread != null) {
            runnerThread.interrupt();
        }
    }

    public void cleanup() {
        stop();
        if (runnerThread != null && runnerThread.isAlive()) {
            try {
                runnerThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public boolean isRunning() {
        return running;
    }

    private void execute(List<CoverageSweepCandidate> candidates,
                         CoverageSweepOptions options,
                         Consumer<AttackResult> resultCallback) {
        safeLog("Coverage sweep starting: " + candidates.size() + " candidate(s); payload set: "
            + options.payloadSet() + (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS
                ? " (uncapped full Bypass catalog)" : " (bounded high-signal probes)"));
        rateLimiter = new RateLimiter(api, options.requestsPerSecond(), options.requestDelayMs(),
            safeThrottleCodes(options.throttleStatusCodes()), options.autoThrottleEnabled());
        int concurrency = Math.max(1, options.concurrency());
        AtomicInteger workerCounter = new AtomicInteger(1);
        executor = Executors.newFixedThreadPool(concurrency, runnable -> {
            Thread thread = new Thread(runnable, "bypassfuzzer-coverage-sweep-worker-" + workerCounter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });

        for (CoverageSweepCandidate candidate : candidates) {
            if (!canContinue()) {
                break;
            }
            executor.submit(() -> {
                try {
                    executeCandidate(candidate, options, resultCallback);
                } catch (Exception e) {
                    safeLogError("Coverage sweep candidate failed for " + candidate.displayUrl() + ": "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
                }
            });
        }

        executor.shutdown();
        try {
            while (canContinue() && !executor.awaitTermination(200, TimeUnit.MILLISECONDS)) {
                // Wait for workers to finish or for stop() to interrupt this runner.
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            if (!executor.isTerminated()) {
                executor.shutdownNow();
            }
        }
        safeLog("Coverage sweep worker pool finished: " + candidates.size() + " candidate(s) submitted; payload set: "
            + options.payloadSet());
    }

    private void executeCandidate(CoverageSweepCandidate candidate,
                                  CoverageSweepOptions options,
                                  Consumer<AttackResult> resultCallback) {
        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(options.requestHeaders());
        HttpResponse controlResponse = null;
        HttpResponse anonymousControlResponse = null;
        HttpRequest verificationRequest = null;
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC
            && options.verifyUnauthenticatedAccess()) {
            ConfiguredHeaderPolicy anonymousPolicy = headerPolicy.withoutAuthentication(
                options.authSelection().headerNames(), options.authSelection().cookieNames());
            HttpRequest anonymousBase = stripAuthentication(candidate.request(), options.authSelection());
            verificationRequest = anonymousPolicy.reconcileMutation(anonymousBase, anonymousBase);
            if (rateLimiter != null && !rateLimiter.waitBeforeRequest()) {
                return;
            }
            anonymousControlResponse = requestSender.send(verificationRequest);
            if (rateLimiter != null && anonymousControlResponse != null) {
                rateLimiter.reportResponse(anonymousControlResponse);
            }
            if (resultCallback != null) {
                String signal = anonymousControlResponse == null
                    ? "No response"
                    : CoverageSweepClassifier.unauthenticatedControlSignal(candidate, anonymousControlResponse);
                resultCallback.accept(new AttackResult(
                    "Authenticated Coverage Sweep",
                    "Original request without authentication",
                    candidate.method() + " " + candidate.displayUrl(),
                    "Unauthenticated Control",
                    signal,
                    verificationRequest,
                    anonymousControlResponse,
                    candidate.request(),
                    candidate.originalResponse(),
                    verificationRequest,
                    anonymousControlResponse
                ));
            }
        }

        for (CoverageSweepProbe probe : buildProbes(candidate, options)) {
            if (!canContinue()) {
                return;
            }
            if (rateLimiter != null && !rateLimiter.waitBeforeRequest()) {
                return;
            }

            HttpResponse response = probe.httpMode() == null
                ? requestSender.send(probe.request())
                : requestSender.send(probe.request(), probe.httpMode());
            if ("Control".equals(probe.family())) {
                controlResponse = response;
            }
            if (rateLimiter != null && response != null) {
                rateLimiter.reportResponse(response);
            }
            if (resultCallback != null) {
                String signal;
                if (response == null) {
                    signal = "No response";
                } else if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
                    if (options.verifyUnauthenticatedAccess()) {
                        signal = CoverageSweepClassifier.authenticatedBypassSignal(
                            candidate, anonymousControlResponse, response);
                        if (signal.isBlank()) {
                            signal = CoverageSweepClassifier.unauthenticatedMutationSignal(
                                anonymousControlResponse, response);
                        }
                    } else {
                        signal = "";
                    }
                } else if ("Control".equals(probe.family())) {
                    signal = "";
                } else {
                    signal = CoverageSweepClassifier.signal(candidate, controlResponse, response);
                }
                HttpResponse originalResponse = candidate.originalResponse() != null
                    ? candidate.originalResponse() : controlResponse;
                resultCallback.accept(new AttackResult(
                    options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC ? "Authenticated Coverage Sweep" : "Coverage Sweep",
                    probe.label(),
                    candidate.method() + " " + candidate.displayUrl(),
                    probe.family(),
                    signal,
                    probe.request(),
                    response,
                    candidate.request(),
                    originalResponse,
                    verificationRequest,
                    anonymousControlResponse
                ));
            }
        }
    }

    private boolean eligible(ProxyHttpRequestResponse item, CoverageSweepOptions options) {
        HttpRequest request = effectiveRequest(item);
        if (item == null || item.response() == null || request == null) {
            return false;
        }
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            int status = item.response().statusCode();
            if (status < 200 || status >= 300) {
                return false;
            }
            if (options.excludeStaticAssets() && isStaticAsset(request, item.response())) {
                return false;
            }
        } else if (!options.statuses().contains((int) item.response().statusCode())) {
            return false;
        }
        if (!options.inScopeOnly()) {
            return true;
        }
        try {
            return isInScope(item);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasSuccessfulResponse(ProxyHttpRequestResponse item) {
        HttpRequest request = effectiveRequest(item);
        if (item == null || request == null || item.response() == null) return false;
        int status = item.response().statusCode();
        return status >= 200 && status < 300;
    }

    private boolean isInScope(ProxyHttpRequestResponse item) {
        if (item == null) {
            return false;
        }

        // Scope belongs to the proxy-history transaction, not to one particular
        // Montoya view of it. In particular, HTTP/2 history entries can report a
        // different scope result from finalRequest() than Burp reports for the
        // history row's final URL. Check every Burp-owned representation and only
        // reject the row when all of them agree that it is out of scope.
        Set<String> urls = new LinkedHashSet<>();
        addScopeUrl(urls, proxyHistoryUrl(item));

        HttpRequest originalRequest = originalRequest(item);
        HttpRequest finalRequest = finalRequest(item);
        if (requestReportsInScope(originalRequest) || requestReportsInScope(finalRequest)) {
            return true;
        }
        addScopeUrl(urls, requestUrl(originalRequest));
        addScopeUrl(urls, requestUrl(finalRequest));

        for (String url : urls) {
            try {
                if (api.scope().isInScope(url)) {
                    return true;
                }
            } catch (RuntimeException | LinkageError ignored) {
            }
        }
        return false;
    }

    private boolean requestReportsInScope(HttpRequest request) {
        if (request == null) return false;
        try {
            return request.isInScope();
        } catch (RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    @SuppressWarnings("removal")
    private String proxyHistoryUrl(ProxyHttpRequestResponse item) {
        try {
            return item.url();
        } catch (RuntimeException | LinkageError ignored) {
            return "";
        }
    }

    private String requestUrl(HttpRequest request) {
        if (request == null) return "";
        try {
            return safeUrl(request);
        } catch (RuntimeException | LinkageError ignored) {
            return "";
        }
    }

    private void addScopeUrl(Set<String> urls, String url) {
        if (url != null && !url.isBlank()) {
            urls.add(url);
        }
    }

    private HttpRequest originalRequest(ProxyHttpRequestResponse item) {
        if (item == null) return null;
        try {
            return item.request();
        } catch (RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private HttpRequest finalRequest(ProxyHttpRequestResponse item) {
        if (item == null) return null;
        try {
            return item.finalRequest();
        } catch (RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private HttpRequest effectiveRequest(ProxyHttpRequestResponse item) {
        HttpRequest finalRequest = finalRequest(item);
        return finalRequest != null ? finalRequest : originalRequest(item);
    }

    private boolean isStaticAsset(HttpRequest request, HttpResponse response) {
        String responseContentType = safe(contentType(response))
            .toLowerCase(Locale.ROOT)
            .split(";", 2)[0]
            .trim();
        if (responseContentType.startsWith("image/")
            || responseContentType.equals("text/css")
            || responseContentType.equals("text/javascript")
            || responseContentType.equals("application/javascript")
            || responseContentType.equals("application/x-javascript")
            || responseContentType.equals("text/ecmascript")
            || responseContentType.equals("application/ecmascript")
            || responseContentType.equals("font/woff")
            || responseContentType.equals("font/woff2")
            || responseContentType.equals("application/font-woff")
            || responseContentType.equals("application/x-font-woff")) {
            return true;
        }

        String path = request == null ? "" : RequestPathUtils.pathWithoutQuery(safe(request.path()))
            .toLowerCase(Locale.ROOT);
        return IMAGE_PATH_PATTERN.matcher(path).matches()
            || JAVASCRIPT_PATH_PATTERN.matcher(path).matches()
            || STYLESHEET_OR_FONT_PATH_PATTERN.matcher(path).matches();
    }

    public boolean matchesAuthSelection(CoverageSweepCandidate candidate, CoverageSweepAuthSelection selection) {
        if (candidate == null || candidate.request() == null || selection == null) {
            return false;
        }
        for (String headerName : selection.headerNames()) {
            if (headerName != null && !headerName.isBlank() && candidate.request().hasHeader(headerName.trim())) {
                return true;
            }
        }
        String cookieHeader = candidate.request().headerValue("Cookie");
        if (cookieHeader == null) {
            return false;
        }
        Set<String> presentCookies = cookieNames(cookieHeader);
        return selection.cookieNames().stream().anyMatch(presentCookies::contains);
    }

    HttpRequest stripAuthentication(HttpRequest request, CoverageSweepAuthSelection selection) {
        HttpRequest stripped = request.withRemovedHeader("Authorization")
            .withRemovedHeader("Proxy-Authorization");
        if (selection != null) {
            for (String headerName : selection.headerNames()) {
                if (headerName != null && !headerName.isBlank()) {
                    stripped = stripped.withRemovedHeader(headerName.trim());
                }
            }
            String cookieHeader = stripped.headerValue("Cookie");
            String retainedCookies = CookieHeaderUtils.removeCookies(cookieHeader, selection.cookieNames());
            if (cookieHeader != null) {
                stripped = stripped.withRemovedHeader("Cookie");
                if (retainedCookies != null && !retainedCookies.isBlank()) {
                    stripped = stripped.withAddedHeader("Cookie", retainedCookies);
                }
            }
        }
        return stripped;
    }

    private List<CoverageSweepProbe> reconcileProbes(List<CoverageSweepProbe> probes,
                                                      HttpRequest baseline,
                                                      ConfiguredHeaderPolicy headerPolicy) {
        return probes.stream()
            .map(probe -> new CoverageSweepProbe(probe.label(), probe.family(),
                headerPolicy.reconcileMutation(baseline, probe.request()), probe.httpMode()))
            .toList();
    }

    private void collectAuthIdentifiers(HttpRequest request, Set<String> headers, Set<String> cookies) {
        try {
            for (HttpHeader header : request.headers()) {
                String name = header.name();
                if (looksLikeAuthHeader(name)) {
                    headers.add(name);
                }
            }
        } catch (Exception ignored) {
        }
        cookies.addAll(cookieNames(request.headerValue("Cookie")));
    }

    private boolean looksLikeAuthHeader(String name) {
        String lower = safe(name).toLowerCase(Locale.ROOT);
        return lower.equals("authorization") || lower.equals("proxy-authorization")
            || lower.contains("auth") || lower.contains("token") || lower.contains("api-key")
            || lower.contains("apikey") || lower.contains("session");
    }

    private Set<String> cookieNames(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return Set.of();
        }
        Set<String> names = new TreeSet<>();
        for (String cookie : cookieHeader.split(";")) {
            int separator = cookie.indexOf('=');
            String name = (separator >= 0 ? cookie.substring(0, separator) : cookie).trim();
            if (!name.isBlank()) names.add(name);
        }
        return names;
    }


    private CoverageSweepCandidate toCandidate(ProxyHttpRequestResponse item) {
        HttpRequest request = effectiveRequest(item);
        HttpResponse response = item.response();
        if (request == null || response == null) {
            return null;
        }

        String displayUrl = safeUrl(request);
        String path = request.path() == null || request.path().isBlank() ? RequestPathUtils.extractPathAndQuery(displayUrl) : request.path();
        return new CoverageSweepCandidate(
            request,
            response,
            dedupeKey(request, displayUrl),
            displayUrl,
            safe(request.method()),
            host(request, displayUrl),
            path,
            response.statusCode(),
            bodyLength(response),
            contentType(response),
            item.time()
        );
    }

    private CoverageSweepCandidate toImportedCandidate(String rawUrl) {
        String displayUrl = normalizeUrl(rawUrl);
        if (displayUrl == null) {
            return null;
        }

        try {
            URI uri = URI.create(displayUrl);
            HttpRequest request = urlRequestFactory.create(uri);
            String path = request.path() == null || request.path().isBlank() ? RequestPathUtils.extractPathAndQuery(displayUrl) : request.path();
            return new CoverageSweepCandidate(
                request,
                null,
                dedupeKey(request, displayUrl),
                displayUrl,
                safe(request.method()),
                host(request, displayUrl),
                path,
                0,
                0,
                "",
                ZonedDateTime.now()
            );
        } catch (Exception e) {
            return null;
        }
    }

    private CoverageSweepCandidate toImportedCandidate(OpenApiOperation operation) {
        String displayUrl = normalizeUrl(operation.url());
        if (displayUrl == null) return null;
        try {
            URI uri = URI.create(displayUrl);
            HttpRequest request = urlRequestFactory.create(uri).withMethod(operation.method());
            for (Map.Entry<String, String> header : operation.headers().entrySet()) {
                request = RequestHeaderUtils.upsertHeader(request, header.getKey(), header.getValue());
            }
            if (!operation.body().isEmpty()) request = request.withBody(operation.body());
            String path = request.path() == null || request.path().isBlank()
                ? RequestPathUtils.extractPathAndQuery(displayUrl) : request.path();
            return new CoverageSweepCandidate(request, null, dedupeKey(request, displayUrl), displayUrl,
                safe(request.method()), host(request, displayUrl), path, 0, 0,
                safe(request.headerValue("Content-Type")), ZonedDateTime.now());
        } catch (Exception e) {
            return null;
        }
    }

    private static HttpRequest defaultImportedRequest(URI uri) {
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
            path += "?" + uri.getRawQuery();
        }

        HttpService service = HttpService.httpService(uri.getHost(), port, secure);
        String rawRequest = "GET " + path + " HTTP/1.1\r\n"
            + "Host: " + hostHeader(uri.getHost(), port, secure) + "\r\n"
            + "\r\n";
        return HttpRequest.httpRequest(service, rawRequest);
    }

    private static String hostHeader(String host, int port, boolean secure) {
        if ((secure && port == 443) || (!secure && port == 80)) {
            return host;
        }
        return host + ":" + port;
    }

    private String normalizeUrl(String rawUrl) {
        if (rawUrl == null) {
            return null;
        }
        String trimmed = rawUrl.trim();
        if (trimmed.isBlank() || trimmed.startsWith("#")) {
            return null;
        }
        try {
            URI uri = URI.create(trimmed);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (host == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                return null;
            }
            return uri.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String dedupeKey(HttpRequest request, String displayUrl) {
        return authorityKey(request, displayUrl)
            + "|" + safe(request.method()).toUpperCase(Locale.ROOT)
            + "|" + normalizedPathShape(request.path())
            + "|" + sortedQueryNames(request.path())
            + "|" + safe(request.headerValue("Content-Type")).toLowerCase(Locale.ROOT);
    }

    private String authorityKey(HttpRequest request, String displayUrl) {
        HttpService service = request.httpService();
        if (service != null && service.host() != null) {
            return (service.secure() ? "https" : "http") + "://" + service.host().toLowerCase(Locale.ROOT) + ":" + service.port();
        }
        try {
            URI uri = URI.create(displayUrl);
            int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
            return safe(uri.getScheme()).toLowerCase(Locale.ROOT) + "://" + safe(uri.getHost()).toLowerCase(Locale.ROOT) + ":" + port;
        } catch (Exception e) {
            return displayUrl;
        }
    }

    private String normalizedPathShape(String pathWithQuery) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String[] parts = path.split("/");
        List<String> normalized = new ArrayList<>();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            String lower = part.toLowerCase(Locale.ROOT);
            if (lower.matches("\\d+")) {
                normalized.add("{num}");
            } else if (lower.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                normalized.add("{uuid}");
            } else {
                normalized.add(lower);
            }
        }
        return "/" + String.join("/", normalized);
    }

    private String sortedQueryNames(String pathWithQuery) {
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        if (query.isBlank()) {
            return "";
        }
        Set<String> names = new TreeSet<>();
        for (String part : query.split("&")) {
            if (part.isBlank()) {
                continue;
            }
            int equals = part.indexOf('=');
            names.add(equals >= 0 ? part.substring(0, equals) : part);
        }
        return String.join(",", names);
    }

    private boolean newer(ZonedDateTime left, ZonedDateTime right) {
        if (left == null) {
            return false;
        }
        if (right == null) {
            return true;
        }
        return left.isAfter(right);
    }

    private String safeUrl(HttpRequest request) {
        try {
            return targetUrlResolver.resolve(request);
        } catch (Exception e) {
            return request.url();
        }
    }

    private String host(HttpRequest request, String displayUrl) {
        try {
            if (request.httpService() != null && request.httpService().host() != null) {
                return request.httpService().host();
            }
        } catch (Exception e) {
            // Fall back to URL parsing.
        }
        try {
            return URI.create(displayUrl).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    private String contentType(HttpResponse response) {
        return response.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
            .map(HttpHeader::value)
            .findFirst()
            .orElse("");
    }

    private int bodyLength(HttpResponse response) {
        return response.body() == null ? 0 : response.body().length();
    }

    private boolean canContinue() {
        return running && !Thread.currentThread().isInterrupted();
    }

    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }

    private void safeLogError(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToError(message);
        } catch (Exception ignored) {
        }
    }

    private Set<Integer> safeThrottleCodes(Set<Integer> codes) {
        return codes == null ? Set.of() : codes;
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    @FunctionalInterface
    interface UrlRequestFactory {
        HttpRequest create(URI uri);
    }
}
