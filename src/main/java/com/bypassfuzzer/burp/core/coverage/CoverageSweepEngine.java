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
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
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

public class CoverageSweepEngine {

    private final MontoyaApi api;
    private final RequestSender requestSender;
    private final CoverageSweepProbeGenerator probeGenerator;
    private final UrlRequestFactory urlRequestFactory;
    private final TargetUrlResolver targetUrlResolver = new TargetUrlResolver();

    private volatile boolean running = false;
    private Thread runnerThread;
    private ExecutorService executor;
    private RateLimiter rateLimiter;

    public CoverageSweepEngine(MontoyaApi api) {
        this(api, new MontoyaRequestSender(api), new CoverageSweepProbeGenerator());
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
        this.urlRequestFactory = urlRequestFactory == null ? CoverageSweepEngine::defaultImportedRequest : urlRequestFactory;
    }

    public CoverageSweepPreview collectPreview(CoverageSweepOptions options) {
        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        List<ProxyHttpRequestResponse> blockedHistory = api.proxy().history(item -> eligible(item, effectiveOptions));
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();

        for (ProxyHttpRequestResponse item : blockedHistory) {
            CoverageSweepCandidate candidate = toCandidate(item);
            if (candidate == null) {
                continue;
            }

            CoverageSweepCandidate existing = deduped.get(candidate.dedupeKey());
            if (existing == null || newer(candidate.time(), existing.time())) {
                deduped.put(candidate.dedupeKey(), candidate);
            }
        }

        List<CoverageSweepCandidate> candidates = new ArrayList<>(deduped.values());
        candidates.sort(Comparator
            .comparing(CoverageSweepCandidate::time, Comparator.nullsLast(Comparator.reverseOrder()))
            .thenComparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        int cap = Math.max(1, effectiveOptions.maxCandidates());
        if (candidates.size() > cap) {
            candidates = new ArrayList<>(candidates.subList(0, cap));
        }

        return new CoverageSweepPreview(blockedHistory.size(), deduped.size(), List.copyOf(candidates));
    }

    public CoverageSweepPreview collectPreviewFromUrls(List<String> urls, CoverageSweepOptions options) {
        if (urls == null || urls.isEmpty()) {
            return new CoverageSweepPreview(0, 0, List.of());
        }

        CoverageSweepOptions effectiveOptions = options == null ? CoverageSweepOptions.defaults() : options;
        Map<String, CoverageSweepCandidate> deduped = new LinkedHashMap<>();
        int parsedTargets = 0;

        for (String url : urls) {
            CoverageSweepCandidate candidate = toImportedCandidate(url);
            if (candidate == null) {
                continue;
            }
            parsedTargets++;
            deduped.putIfAbsent(candidate.dedupeKey(), candidate);
        }

        List<CoverageSweepCandidate> candidates = new ArrayList<>(deduped.values());
        candidates.sort(Comparator.comparing(CoverageSweepCandidate::displayUrl, Comparator.nullsLast(String::compareTo)));

        int cap = Math.max(1, effectiveOptions.maxCandidates());
        if (candidates.size() > cap) {
            candidates = new ArrayList<>(candidates.subList(0, cap));
        }

        return new CoverageSweepPreview(parsedTargets, deduped.size(), List.copyOf(candidates));
    }

    public List<CoverageSweepProbe> buildProbes(CoverageSweepCandidate candidate, CoverageSweepOptions options) {
        if (candidate == null) {
            return List.of();
        }
        return probeGenerator.buildProbes(candidate.request(), options == null ? CoverageSweepOptions.defaults() : options);
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
        rateLimiter = new RateLimiter(api, options.requestsPerSecond(), safeThrottleCodes(options.throttleStatusCodes()), !safeThrottleCodes(options.throttleStatusCodes()).isEmpty());
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
            executor.submit(() -> executeCandidate(candidate, options, resultCallback));
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
    }

    private void executeCandidate(CoverageSweepCandidate candidate,
                                  CoverageSweepOptions options,
                                  Consumer<AttackResult> resultCallback) {
        HttpResponse controlResponse = null;
        for (CoverageSweepProbe probe : buildProbes(candidate, options)) {
            if (!canContinue()) {
                return;
            }
            if (rateLimiter != null && !rateLimiter.waitBeforeRequest()) {
                return;
            }

            HttpResponse response = requestSender.send(probe.request());
            if ("Control".equals(probe.family())) {
                controlResponse = response;
            }
            if (rateLimiter != null && response != null) {
                rateLimiter.reportResponse(response.statusCode());
            }
            if (resultCallback != null) {
                String signal = "Control".equals(probe.family()) ? "" : CoverageSweepClassifier.signal(candidate, controlResponse, response);
                resultCallback.accept(new AttackResult(
                    "Coverage Sweep",
                    probe.label(),
                    candidate.method() + " " + candidate.path(),
                    probe.family(),
                    signal,
                    probe.request(),
                    response
                ));
            }
        }
    }

    private boolean eligible(ProxyHttpRequestResponse item, CoverageSweepOptions options) {
        if (item == null || !item.hasResponse() || item.response() == null || item.request() == null) {
            return false;
        }
        if (!options.statuses().contains((int) item.response().statusCode())) {
            return false;
        }
        if (!options.inScopeOnly()) {
            return true;
        }
        try {
            HttpRequest request = item.finalRequest() != null ? item.finalRequest() : item.request();
            return api.scope().isInScope(safeUrl(request));
        } catch (Exception e) {
            return false;
        }
    }

    private CoverageSweepCandidate toCandidate(ProxyHttpRequestResponse item) {
        HttpRequest request = item.finalRequest() != null ? item.finalRequest() : item.request();
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
