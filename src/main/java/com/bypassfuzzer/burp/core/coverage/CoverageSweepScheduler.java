package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

/** Coordinates global pacing with independent concurrency and backoff per host. */
final class CoverageSweepScheduler {

    private final Semaphore globalPermits;
    private final RateLimiter globalLimiter;
    private final int perHostConcurrency;
    private final MontoyaApi api;
    private final Set<Integer> throttleStatusCodes;
    private final boolean autoThrottleEnabled;
    private final boolean smartThrottleEnabled;
    private final long perHostDelayMs;
    private final ConcurrentHashMap<String, HostState> hosts = new ConcurrentHashMap<>();

    /** Minimum per-host concurrency when smart throttle manages its own bursts. */
    static final int SMART_THROTTLE_MIN_PER_HOST = 50;

    CoverageSweepScheduler(MontoyaApi api, CoverageSweepOptions options) {
        this.api = api;
        this.smartThrottleEnabled = options.smartThrottleEnabled();
        this.autoThrottleEnabled = options.autoThrottleEnabled();
        this.throttleStatusCodes = options.throttleStatusCodes() == null
            ? Set.of() : Set.copyOf(options.throttleStatusCodes());

        if (smartThrottleEnabled) {
            // Smart throttle manages its own burst pacing; raise concurrency floors
            // so semaphores don't bottleneck bursts.
            int effectivePerHost = Math.max(options.perHostConcurrency(), SMART_THROTTLE_MIN_PER_HOST);
            int effectiveGlobal = Math.max(options.concurrency(), effectivePerHost * 4);
            this.perHostConcurrency = effectivePerHost;
            this.globalPermits = new Semaphore(effectiveGlobal, true);
            this.perHostDelayMs = 0; // smart throttle handles pacing
        } else {
            this.perHostConcurrency = Math.max(1, options.perHostConcurrency());
            this.globalPermits = new Semaphore(Math.max(1, options.concurrency()), true);
            this.perHostDelayMs = Math.max(0, options.requestDelayMs());
        }

        this.globalLimiter = new RateLimiter(api, options.requestsPerSecond(),
            smartThrottleEnabled ? 0 : options.requestDelayMs(), Set.of(), false, "global");
    }

    HttpResponse send(HttpRequest request, Supplier<HttpResponse> sender) {
        String hostKey = hostKey(request);
        HostState host = hosts.computeIfAbsent(hostKey, ignored -> new HostState(hostKey));
        boolean globalAcquired = false;
        boolean hostAcquired = false;
        try {
            globalPermits.acquire();
            globalAcquired = true;
            host.permits.acquire();
            hostAcquired = true;
            long globalEpoch = globalLimiter.waitBeforeRequest();
            if (globalEpoch < 0) {
                return null;
            }
            long hostEpoch = host.limiter.waitBeforeRequest();
            if (hostEpoch < 0) {
                return null;
            }
            HttpResponse response = sender.get();
            if (response != null) {
                host.limiter.reportResponse(response, hostEpoch);
            }
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (hostAcquired) host.permits.release();
            if (globalAcquired) globalPermits.release();
        }
    }

    private String hostKey(HttpRequest request) {
        try {
            URI uri = URI.create(request.url());
            int port = uri.getPort();
            if (port < 0) port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            return (uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase())
                + "://" + uri.getHost().toLowerCase() + ":" + port;
        } catch (Exception ignored) {
            try {
                return request.httpService().toString();
            } catch (Exception ignoredAgain) {
                return "unknown-host";
            }
        }
    }

    private final class HostState {
        private final Semaphore permits = new Semaphore(perHostConcurrency, true);
        private final RateLimiter limiter;

        private HostState(String hostKey) {
            this.limiter = new RateLimiter(api, 0, perHostDelayMs, throttleStatusCodes,
                autoThrottleEnabled, hostKey);
            if (smartThrottleEnabled) {
                this.limiter.enableSmartThrottle(true);
            }
        }
    }
}
