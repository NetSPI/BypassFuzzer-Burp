package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Global request pacing and response-driven backoff shared by all workers. */
public class RateLimiter {

    private static final long INITIAL_BACKOFF_MS = 1000;
    private static final long MAX_BACKOFF_MS = 60_000;

    private final MontoyaApi api;
    private final Set<Integer> throttleStatusCodes;
    private final boolean autoThrottleEnabled;
    private final long fixedDelayMs;
    private volatile int requestsPerSecond;
    private volatile long adaptiveDelayMs;
    private long nextRequestNanos;
    private long blockedUntilEpochMs;
    private long nextBackoffAdjustmentEpochMs;

    public RateLimiter(MontoyaApi api, int requestsPerSecond, Set<Integer> throttleStatusCodes,
                       boolean autoThrottleEnabled) {
        this(api, requestsPerSecond, 0, throttleStatusCodes, autoThrottleEnabled);
    }

    public RateLimiter(MontoyaApi api, int requestsPerSecond, long fixedDelayMs,
                       Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled) {
        this.api = api;
        this.requestsPerSecond = Math.max(0, requestsPerSecond);
        this.fixedDelayMs = Math.max(0, fixedDelayMs);
        this.throttleStatusCodes = throttleStatusCodes == null ? Set.of() : Set.copyOf(throttleStatusCodes);
        this.autoThrottleEnabled = autoThrottleEnabled;
    }

    /** Reserves the next globally paced request slot. */
    public synchronized boolean waitBeforeRequest() {
        while (!Thread.currentThread().isInterrupted()) {
            long nowNanos = System.nanoTime();
            long backoffMs = Math.max(0, blockedUntilEpochMs - System.currentTimeMillis());
            long waitNanos = Math.max(nextRequestNanos - nowNanos, TimeUnit.MILLISECONDS.toNanos(backoffMs));
            if (waitNanos <= 0) {
                nextRequestNanos = nowNanos + effectiveDelayNanos();
                return true;
            }
            try {
                TimeUnit.NANOSECONDS.timedWait(this, waitNanos);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    public void reportResponse(int statusCode) {
        reportResponse(statusCode, null);
    }

    public void reportResponse(HttpResponse response) {
        if (response != null) {
            reportResponse(response.statusCode(), response.headerValue("Retry-After"));
        }
    }

    private synchronized void reportResponse(int statusCode, String retryAfter) {
        if (!autoThrottleEnabled || !throttleStatusCodes.contains(statusCode)) {
            return;
        }

        long now = System.currentTimeMillis();
        long retryAfterMs = parseRetryAfterMs(retryAfter, now);
        if (retryAfterMs > 0) {
            blockedUntilEpochMs = Math.max(blockedUntilEpochMs, now + retryAfterMs);
        }

        // React to the first configured status, but do not amplify a burst of
        // responses that were already in flight before the backoff took effect.
        if (now >= nextBackoffAdjustmentEpochMs) {
            long configuredDelay = baseDelayMs();
            long base = configuredDelay == 0
                ? INITIAL_BACKOFF_MS
                : Math.min(MAX_BACKOFF_MS, Math.max(INITIAL_BACKOFF_MS, configuredDelay * 2));
            adaptiveDelayMs = adaptiveDelayMs == 0 ? base : Math.min(MAX_BACKOFF_MS, adaptiveDelayMs * 2);
            nextBackoffAdjustmentEpochMs = now + adaptiveDelayMs;
        }
        notifyAll();
        safeLog(String.format("Auto-throttle: HTTP %d; pacing requests at least %d ms apart%s.",
            statusCode, effectiveDelayMs(), retryAfterMs > 0 ? ", honoring Retry-After" : ""));
    }

    private long parseRetryAfterMs(String value, long nowEpochMs) {
        if (value == null || value.isBlank()) return 0;
        try {
            return TimeUnit.SECONDS.toMillis(Math.max(0, Long.parseLong(value.trim())));
        } catch (NumberFormatException ignored) {
            try {
                return Math.max(0, ZonedDateTime.parse(value.trim(), DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant().toEpochMilli() - nowEpochMs);
            } catch (Exception invalidDate) {
                return 0;
            }
        }
    }

    public synchronized void updateRateLimit(int requestsPerSecond) {
        this.requestsPerSecond = Math.max(0, requestsPerSecond);
        notifyAll();
    }

    private long baseDelayMs() {
        long rpsDelay = requestsPerSecond <= 0 ? 0 : (long) Math.ceil(1000.0 / requestsPerSecond);
        return Math.max(fixedDelayMs, rpsDelay);
    }

    private long effectiveDelayMs() {
        return Math.max(baseDelayMs(), adaptiveDelayMs);
    }

    private long effectiveDelayNanos() {
        return TimeUnit.MILLISECONDS.toNanos(effectiveDelayMs());
    }

    public int getCurrentRequestsPerSecond() {
        long delay = effectiveDelayMs();
        return delay == 0 ? requestsPerSecond : Math.max(1, (int) (1000 / delay));
    }

    public long getCurrentDelayMs() {
        return effectiveDelayMs();
    }

    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }
}
