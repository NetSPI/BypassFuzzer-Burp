package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.Map;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The single admission funnel every scan pipeline routes requests through. It keeps one
 * {@link AdaptiveRateController} per host (keyed by {@code scheme://host:port}) so each host's
 * rate-limit ceiling is discovered and ridden independently, and bounds in-flight concurrency with a
 * global safety semaphore plus a per-host semaphore.
 *
 * <p>Pacing is done entirely by the per-host controller's token bucket; the semaphores are only a
 * resource cap on how many requests may be outstanding at once, never the rate control.</p>
 */
public final class HostThrottleCoordinator {

    private final ThrottleSettings settings;
    private final Consumer<String> logger;
    private final LongSupplier nanoTime;
    private final LongSupplier currentTimeMillis;
    private final AdaptiveRateController.Tuning tuningOverride;
    private final Semaphore globalPermits;
    private final Map<String, HostState> hosts = new ConcurrentHashMap<>();
    private final Object globalPauseLock = new Object();
    private final Deque<Long> recentThrottleTimes = new ArrayDeque<>();
    private long globalPauseUntilMillis;
    private long lastThrottleMillis;
    private int smartPauseLevel;

    public HostThrottleCoordinator(ThrottleSettings settings, MontoyaApi api) {
        this(settings, loggerFor(api), System::nanoTime, System::currentTimeMillis, null);
    }

    HostThrottleCoordinator(ThrottleSettings settings, Consumer<String> logger,
                            LongSupplier nanoTime, LongSupplier currentTimeMillis,
                            AdaptiveRateController.Tuning tuningOverride) {
        this.settings = settings == null ? ThrottleSettings.defaults() : settings;
        this.logger = logger;
        this.nanoTime = nanoTime;
        this.currentTimeMillis = currentTimeMillis;
        this.tuningOverride = tuningOverride;
        this.globalPermits = new Semaphore(this.settings.globalConcurrency(), true);
    }

    /**
     * Paces and sends one request through the supplied sender, feeding the response back into the
     * host's adaptive controller.
     *
     * @return the response, or {@code null} if the send failed or the thread was interrupted.
     */
    public HttpResponse send(HttpRequest request, Supplier<HttpResponse> sender) {
        HostState host = hosts.computeIfAbsent(hostKey(request), HostState::new);
        boolean globalAcquired = false;
        boolean hostAcquired = false;
        try {
            if (!awaitGlobalPause()) {
                return null;
            }
            globalPermits.acquire();
            globalAcquired = true;
            host.permits.acquire();
            hostAcquired = true;

            // A throttle may have triggered a global CDN/WAF cooldown while this worker was
            // waiting for an in-flight permit.
            if (!awaitGlobalPause()) {
                return null;
            }

            long generation = host.controller.acquire();
            if (generation < 0) {
                return null;
            }
            HttpResponse response = sender.get();
            if (response != null) {
                host.controller.report(response.statusCode(), retryAfter(response), generation);
                reportGlobalThrottle(response);
            }
            return response;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (hostAcquired) {
                host.permits.release();
            }
            if (globalAcquired) {
                globalPermits.release();
            }
        }
    }

    private boolean awaitGlobalPause() {
        synchronized (globalPauseLock) {
            while (true) {
                long remaining = globalPauseUntilMillis - currentTimeMillis.getAsLong();
                if (remaining <= 0) {
                    return true;
                }
                try {
                    globalPauseLock.wait(Math.min(remaining, 1_000L));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
    }

    private void reportGlobalThrottle(HttpResponse response) {
        if (settings.pauseMode() == ThrottleSettings.PauseMode.OFF
            || !settings.throttleStatusCodes().contains((int) response.statusCode())) {
            return;
        }
        long now = currentTimeMillis.getAsLong();
        long retryAfterMillis = retryAfterMillis(retryAfter(response), now);
        synchronized (globalPauseLock) {
            if (settings.pauseMode() == ThrottleSettings.PauseMode.FIXED) {
                beginGlobalPause(now, Math.max(settings.fixedPauseMillis(), retryAfterMillis), "fixed");
                return;
            }

            if (lastThrottleMillis > 0 && now - lastThrottleMillis > 60_000L) {
                smartPauseLevel = 0;
                recentThrottleTimes.clear();
            }
            lastThrottleMillis = now;
            recentThrottleTimes.addLast(now);
            while (!recentThrottleTimes.isEmpty() && now - recentThrottleTimes.peekFirst() > 3_000L) {
                recentThrottleTimes.removeFirst();
            }
            if (recentThrottleTimes.size() >= 3) {
                long computed = Math.min(120_000L, 10_000L << Math.min(smartPauseLevel, 4));
                smartPauseLevel++;
                recentThrottleTimes.clear();
                beginGlobalPause(now, Math.max(computed, retryAfterMillis), "smart");
            }
        }
    }

    private void beginGlobalPause(long now, long durationMillis, String mode) {
        globalPauseUntilMillis = Math.max(globalPauseUntilMillis, now + durationMillis);
        logger.accept("Global " + mode + " throttle pause: " + durationMillis
            + " ms before Sweep requests resume.");
        globalPauseLock.notifyAll();
    }

    private long retryAfterMillis(String value, long nowMillis) {
        if (value == null || value.isBlank()) return 0L;
        try {
            return Math.max(0L, Long.parseLong(value.trim()) * 1_000L);
        } catch (NumberFormatException ignored) {
            try {
                return Math.max(0L, java.time.ZonedDateTime.parse(value.trim()).toInstant().toEpochMilli() - nowMillis);
            } catch (Exception ignoredAgain) {
                return 0L;
            }
        }
    }

    /** True if the given status code is treated as a rate-limit signal. */
    public boolean isThrottleStatusCode(int statusCode) {
        return settings.throttleStatusCodes().contains(statusCode);
    }

    /** Current adaptive rate (req/s) for a host, or 0 if none seen yet. Telemetry for the UI. */
    public double currentRateForHost(String hostKey) {
        HostState host = hosts.get(hostKey);
        return host == null ? 0 : host.controller.currentRatePerSecond();
    }

    /** The per-host controller, exposed for tests and telemetry. */
    AdaptiveRateController controllerForHost(String hostKey) {
        HostState host = hosts.get(hostKey);
        return host == null ? null : host.controller;
    }

    /** Remaining Sweep-wide CDN/WAF cooldown, exposed for tests and telemetry. */
    long globalPauseRemainingMillis() {
        synchronized (globalPauseLock) {
            return Math.max(0L, globalPauseUntilMillis - currentTimeMillis.getAsLong());
        }
    }

    static String hostKey(HttpRequest request) {
        try {
            URI uri = URI.create(request.url());
            int port = uri.getPort();
            if (port < 0) {
                port = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
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

    private static String retryAfter(HttpResponse response) {
        try {
            return response.headerValue("Retry-After");
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Consumer<String> loggerFor(MontoyaApi api) {
        if (api == null) {
            return message -> {};
        }
        return message -> {
            try {
                if (api.logging() != null) {
                    api.logging().logToOutput(message);
                }
            } catch (Exception ignored) {
                // logging is best-effort
            }
        };
    }

    private final class HostState {
        private final AdaptiveRateController controller;
        private final Semaphore permits = new Semaphore(settings.perHostConcurrency(), true);

        private HostState(String hostKey) {
            AdaptiveRateController.Tuning tuning = tuningOverride != null ? tuningOverride : settings.tuning();
            this.controller = new AdaptiveRateController(tuning,
                settings.throttleStatusCodes(), nanoTime, currentTimeMillis, hostKey, logger);
        }
    }
}
