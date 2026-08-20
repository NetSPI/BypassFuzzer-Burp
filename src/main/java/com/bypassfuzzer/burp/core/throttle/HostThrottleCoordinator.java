package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.Map;
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
            globalPermits.acquire();
            globalAcquired = true;
            host.permits.acquire();
            hostAcquired = true;

            long generation = host.controller.acquire();
            if (generation < 0) {
                return null;
            }
            HttpResponse response = sender.get();
            if (response != null) {
                host.controller.report(response.statusCode(), retryAfter(response), generation);
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
