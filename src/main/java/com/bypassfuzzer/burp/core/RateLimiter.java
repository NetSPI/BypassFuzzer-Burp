package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/** Global request pacing and response-driven backoff shared by all workers. */
public class RateLimiter {

    private static final long INITIAL_BACKOFF_MS = 1000;
    private static final long MAX_BACKOFF_MS = 60_000;
    private static final long MIN_RECOVERY_WINDOW_MS = 5_000;
    private static final long INITIAL_SILENT_WAIT_MS = 60_000;
    private static final long MIN_COOLDOWN_MS = 1_000;
    private static final int CLEAN_CYCLES_BEFORE_ADJUST = 5;
    private static final int CALIBRATION_MAX_REQUESTS = 50;
    static final int MAX_RETRY_QUEUE_SIZE = 5000;

    private final MontoyaApi api;
    private final Set<Integer> throttleStatusCodes;
    private final boolean autoThrottleEnabled;
    private final long fixedDelayMs;
    private final String scopeLabel;
    private final LongSupplier currentTimeMillis;
    private final LongSupplier nanoTime;
    private volatile int requestsPerSecond;
    private volatile long adaptiveDelayMs;
    private long nextRequestNanos;
    private long blockedUntilEpochMs;
    private long nextBackoffAdjustmentEpochMs;
    private long nextRecoveryAdjustmentEpochMs;
    private long adaptiveDelayFloorMs;

    // Smart throttle state
    private volatile boolean smartThrottleEnabled = false;
    private int burstSize = 0;           // 0 = not calibrated yet
    private int calibratedBurstSize = 0; // original burst from calibration (reference for mid-burst decisions)
    private long cooldownMs = 0;         // 0 = not calibrated yet
    private int burstSent = 0;           // permits granted in current burst
    private int burstSuccessCount = 0;   // successful responses in current burst
    private int calibrationRequestCount = 0; // permits granted during calibration (for logging)
    private int calibrationSuccessCount = 0; // successful responses during calibration
    private int successBeforeThrottle = 0; // last observed safe count
    private long burstCooldownUntilNanos = 0;
    private long firstThrottleMs = 0;    // when the current throttle started
    private boolean calibrating = false;
    private boolean probing = false;
    private boolean singleRequestInFlight = false; // true while a serialized request (calibration or probe) is outstanding
    private long silentWaitMs = 0;       // current silent wait duration (doubles on each failed probe)
    private long silentWaitUntilNanos = 0; // nanoTime when silent wait ends and probe is allowed
    private int consecutiveCleanCycles = 0;
    private SmartThrottlePhase smartPhase = SmartThrottlePhase.CALIBRATING_BURST;

    // Epoch counter: incremented on every state transition (calibration->probing,
    // probing->running, etc). Responses from a previous epoch are stale (in-flight
    // from before the transition) and are ignored by the smart throttle state machine.
    private long smartEpoch = 0;

    enum SmartThrottlePhase {
        CALIBRATING_BURST, RUNNING, ADJUSTING
    }

    // Retry queue for throttled requests
    private final ConcurrentLinkedQueue<ThrottledRequest> retryQueue = new ConcurrentLinkedQueue<>();

    public RateLimiter(MontoyaApi api, int requestsPerSecond, Set<Integer> throttleStatusCodes,
                       boolean autoThrottleEnabled) {
        this(api, requestsPerSecond, 0, throttleStatusCodes, autoThrottleEnabled);
    }

    public RateLimiter(MontoyaApi api, int requestsPerSecond, long fixedDelayMs,
                       Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled) {
        this(api, requestsPerSecond, fixedDelayMs, throttleStatusCodes, autoThrottleEnabled,
            System::currentTimeMillis, System::nanoTime, "");
    }

    public RateLimiter(MontoyaApi api, int requestsPerSecond, long fixedDelayMs,
                       Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled,
                       String scopeLabel) {
        this(api, requestsPerSecond, fixedDelayMs, throttleStatusCodes, autoThrottleEnabled,
            System::currentTimeMillis, System::nanoTime, scopeLabel);
    }

    RateLimiter(MontoyaApi api, int requestsPerSecond, long fixedDelayMs,
                Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled,
                LongSupplier currentTimeMillis, LongSupplier nanoTime) {
        this(api, requestsPerSecond, fixedDelayMs, throttleStatusCodes, autoThrottleEnabled,
            currentTimeMillis, nanoTime, "");
    }

    RateLimiter(MontoyaApi api, int requestsPerSecond, long fixedDelayMs,
                Set<Integer> throttleStatusCodes, boolean autoThrottleEnabled,
                LongSupplier currentTimeMillis, LongSupplier nanoTime, String scopeLabel) {
        this.api = api;
        this.requestsPerSecond = Math.max(0, requestsPerSecond);
        this.fixedDelayMs = Math.max(0, fixedDelayMs);
        this.throttleStatusCodes = throttleStatusCodes == null ? Set.of() : Set.copyOf(throttleStatusCodes);
        this.autoThrottleEnabled = autoThrottleEnabled;
        this.currentTimeMillis = currentTimeMillis;
        this.nanoTime = nanoTime;
        this.scopeLabel = scopeLabel == null ? "" : scopeLabel;
    }

    /**
     * Reserves the next globally paced request slot.
     *
     * @return the epoch on success (>= 0), or -1 on failure (interrupted / cancelled).
     *         For legacy (non-smart) mode the epoch is always 0.
     *         Callers should pass the returned epoch to {@link #reportResponse(HttpResponse, long)}
     *         or {@link #reportResponse(int, long)} so stale responses from a previous epoch
     *         are filtered correctly -- even when the response arrives on a different thread.
     */
    public synchronized long waitBeforeRequest() {
        if (smartThrottleEnabled) {
            return waitBeforeRequestSmart();
        }
        return waitBeforeRequestLegacy();
    }

    private long waitBeforeRequestLegacy() {
        while (!Thread.currentThread().isInterrupted()) {
            long nowNanos = nanoTime.getAsLong();
            long backoffMs = Math.max(0, blockedUntilEpochMs - currentTimeMillis.getAsLong());
            long waitNanos = Math.max(nextRequestNanos - nowNanos, TimeUnit.MILLISECONDS.toNanos(backoffMs));
            if (waitNanos <= 0) {
                nextRequestNanos = nowNanos + effectiveDelayNanos();
                return 0;
            }
            try {
                TimeUnit.NANOSECONDS.timedWait(this, waitNanos);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        }
        return -1;
    }

    private long waitBeforeRequestSmart() {
        while (!Thread.currentThread().isInterrupted()) {
            long nowNanos = nanoTime.getAsLong();

            // During calibration: serialize -- one request at a time for accurate counting
            if (calibrating && !probing) {
                if (singleRequestInFlight) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return -1;
                    }
                    continue;
                }
                singleRequestInFlight = true;
                calibrationRequestCount++;
                return smartEpoch;
            }

            // During probing: wait silently, then allow exactly one probe at a time
            if (probing) {
                if (nowNanos < silentWaitUntilNanos) {
                    long waitNanos = silentWaitUntilNanos - nowNanos;
                    try {
                        TimeUnit.NANOSECONDS.timedWait(this, waitNanos);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return -1;
                    }
                    continue;
                }
                if (singleRequestInFlight) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return -1;
                    }
                    continue;
                }
                singleRequestInFlight = true;
                return smartEpoch;
            }

            // No rate limit detected (burstSize==0 after calibration): grant immediately
            if (burstSize == 0) {
                return smartEpoch;
            }

            // Calibrated and RUNNING: enforce burst + cooldown
            // In cooldown?
            if (nowNanos < burstCooldownUntilNanos) {
                long cooldownWaitNanos = burstCooldownUntilNanos - nowNanos;
                try {
                    TimeUnit.NANOSECONDS.timedWait(this, cooldownWaitNanos);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return -1;
                }
                continue;
            }

            // Burst budget available?
            if (burstSent < burstSize) {
                burstSent++;
                return smartEpoch;
            }

            // Burst exhausted: enter cooldown
            burstCooldownUntilNanos = nowNanos + TimeUnit.MILLISECONDS.toNanos(cooldownMs);
            burstSent = 0;
            burstSuccessCount = 0;
            safeLog(String.format("Smart throttle%s: burst exhausted, cooldown %ds.",
                scopeSuffix(), cooldownMs / 1000));
            notifyAll();
        }
        return -1;
    }

    /** Report a response without epoch filtering (legacy callers). */
    public void reportResponse(int statusCode) {
        reportResponse(statusCode, (String) null);
    }

    /** Report a response without epoch filtering (legacy callers). */
    public void reportResponse(HttpResponse response) {
        if (response != null) {
            reportResponse(response.statusCode(), response.headerValue("Retry-After"));
        }
    }

    /**
     * Report a response with an explicit epoch captured from {@link #waitBeforeRequest()}.
     * The epoch ensures stale responses from a previous smart-throttle phase are ignored,
     * even when the response arrives on a different thread.
     */
    public void reportResponse(HttpResponse response, long epoch) {
        if (response != null) {
            reportResponseWithEpoch(response.statusCode(), response.headerValue("Retry-After"), epoch);
        }
    }

    /** Report a response with an explicit epoch. */
    public void reportResponse(int statusCode, long epoch) {
        reportResponseWithEpoch(statusCode, null, epoch);
    }

    private synchronized void reportResponse(int statusCode, String retryAfter) {
        if (smartThrottleEnabled) {
            reportResponseSmart(statusCode, -1);
            return;
        }
        reportResponseLegacy(statusCode, retryAfter);
    }

    private synchronized void reportResponseWithEpoch(int statusCode, String retryAfter, long epoch) {
        if (smartThrottleEnabled) {
            reportResponseSmart(statusCode, epoch);
            return;
        }
        reportResponseLegacy(statusCode, retryAfter);
    }

    private void reportResponseLegacy(int statusCode, String retryAfter) {
        if (!autoThrottleEnabled) {
            return;
        }

        long now = currentTimeMillis.getAsLong();
        if (!throttleStatusCodes.contains(statusCode)) {
            recoverAfterSuccessfulResponse(now);
            return;
        }

        long retryAfterMs = parseRetryAfterMs(retryAfter, now);
        if (retryAfterMs > 0) {
            blockedUntilEpochMs = Math.max(blockedUntilEpochMs, now + retryAfterMs);
        }

        // React to the first configured status, but do not amplify a burst of
        // responses that were already in flight before the backoff took effect.
        if (now >= nextBackoffAdjustmentEpochMs) {
            long previousAdaptive = adaptiveDelayMs;
            long configuredDelay = baseDelayMs();
            long base = configuredDelay == 0
                ? INITIAL_BACKOFF_MS
                : Math.min(MAX_BACKOFF_MS, Math.max(INITIAL_BACKOFF_MS, configuredDelay * 2));
            adaptiveDelayMs = adaptiveDelayMs == 0 ? base : Math.min(MAX_BACKOFF_MS, adaptiveDelayMs * 2);
            if (previousAdaptive > 0) {
                adaptiveDelayFloorMs = Math.max(adaptiveDelayFloorMs, adaptiveDelayMs);
            }
            nextBackoffAdjustmentEpochMs = now + adaptiveDelayMs;
        }
        nextRecoveryAdjustmentEpochMs = now + recoveryWindowMs();

        // A response can arrive while another worker is already waiting on the
        // previously calculated schedule. Push that shared gate forward now so
        // the first post-throttle request cannot slip through at the old rate.
        long throttledNextRequest = nanoTime.getAsLong() + effectiveDelayNanos();
        nextRequestNanos = Math.max(nextRequestNanos, throttledNextRequest);
        notifyAll();
        safeLog(String.format("Auto-throttle%s: HTTP %d; pacing requests at least %d ms apart%s.",
            scopeSuffix(),
            statusCode, effectiveDelayMs(), retryAfterMs > 0 ? ", honoring Retry-After" : ""));
    }

    private void reportResponseSmart(int statusCode, long epoch) {
        // Ignore responses from a previous epoch. These are in-flight requests
        // granted before a state transition (e.g. calibration->probing, burst->probing).
        // Their responses are stale and must not corrupt the current state.
        if (epoch >= 0 && epoch != smartEpoch) {
            return;
        }

        boolean isThrottle = throttleStatusCodes.contains(statusCode);

        if (calibrating && !probing) {
            // CALIBRATING_BURST phase: serialized, one request at a time for accurate counting
            singleRequestInFlight = false;
            if (isThrottle) {
                successBeforeThrottle = calibrationSuccessCount;
                firstThrottleMs = currentTimeMillis.getAsLong();
                probing = true;
                silentWaitMs = INITIAL_SILENT_WAIT_MS;
                silentWaitUntilNanos = nanoTime.getAsLong() + TimeUnit.MILLISECONDS.toNanos(silentWaitMs);
                safeLog(String.format("Smart throttle%s: throttle at request #%d (%d succeeded), waiting %ds before probing.",
                    scopeSuffix(), calibrationRequestCount, successBeforeThrottle, silentWaitMs / 1000));
            } else {
                calibrationSuccessCount++;
                if (calibrationSuccessCount >= CALIBRATION_MAX_REQUESTS) {
                    // No throttle seen after enough successful responses
                    calibrating = false;
                    burstSize = 0;
                    smartPhase = SmartThrottlePhase.RUNNING;
                    safeLog(String.format("Smart throttle%s: no rate limit detected after %d requests, running unlimited.",
                        scopeSuffix(), calibrationSuccessCount));
                }
            }
            notifyAll(); // Wake next calibration request (or all threads if state changed)
            return;
        }

        if (probing) {
            // Probe responses are serialized (singleRequestInFlight flag) so this is safe
            singleRequestInFlight = false;
            if (!isThrottle) {
                // Rate limit has reset -- this is a real probe success (serialized, current epoch)
                long resetDuration = currentTimeMillis.getAsLong() - firstThrottleMs;
                if (calibrating) {
                    if (successBeforeThrottle == 0) {
                        // Re-calibration from unlimited mode: got 429 with 0 successes.
                        // Rate limit just reset -- start fresh calibration from scratch.
                        calibrating = true;
                        probing = false;
                        calibrationRequestCount = 0;
                        calibrationSuccessCount = 0;
                        successBeforeThrottle = 0;
                        smartPhase = SmartThrottlePhase.CALIBRATING_BURST;
                        smartEpoch++;
                        safeLog(String.format("Smart throttle%s: reset detected, starting fresh calibration.",
                            scopeSuffix()));
                    } else {
                        // First calibration: set initial burst and cooldown
                        burstSize = Math.max(1, (int) (successBeforeThrottle * 0.85));
                        calibratedBurstSize = burstSize;
                        cooldownMs = Math.max(MIN_COOLDOWN_MS, (long) (resetDuration * 1.1));
                        calibrating = false;
                        probing = false;
                        burstSent = 0;
                        burstSuccessCount = 0;
                        consecutiveCleanCycles = 0;
                        smartPhase = SmartThrottlePhase.RUNNING;
                        smartEpoch++;
                        safeLog(String.format("Smart throttle%s: calibrated burst=%d, cooldown=%ds.",
                            scopeSuffix(), burstSize, cooldownMs / 1000));
                    }
                } else {
                    // Mid-run reset after a throttle
                    long newCooldown = Math.max(MIN_COOLDOWN_MS, (long) (resetDuration * 1.1));
                    if (newCooldown > cooldownMs) {
                        cooldownMs = newCooldown;
                    }
                    probing = false;
                    burstSent = 0;
                    burstSuccessCount = 0;
                    smartPhase = SmartThrottlePhase.RUNNING;
                    smartEpoch++;
                    safeLog(String.format("Smart throttle%s: reset detected, burst=%d, cooldown=%ds.",
                        scopeSuffix(), burstSize, cooldownMs / 1000));
                }
                notifyAll();
                return; // Probe succeeded -- do NOT fall through to "still throttled"
            }
            // Still throttled: double the silent wait and try again
            silentWaitMs *= 2;
            silentWaitUntilNanos = nanoTime.getAsLong() + TimeUnit.MILLISECONDS.toNanos(silentWaitMs);
            safeLog(String.format("Smart throttle%s: probe still throttled, waiting %ds before next probe.",
                scopeSuffix(), silentWaitMs / 1000));
            notifyAll();
            return;
        }

        // RUNNING / ADJUSTING phase
        if (burstSize == 0) {
            // Unlimited mode - no calibration was needed, but if we suddenly get throttled,
            // wait for rate limit to reset, then start fresh calibration.
            if (isThrottle) {
                calibrating = true;
                probing = true; // Wait for reset before calibrating
                singleRequestInFlight = false;
                burstSent = 0;
                burstSuccessCount = 0;
                successBeforeThrottle = 0;
                calibrationRequestCount = 0;
                calibrationSuccessCount = 0;
                firstThrottleMs = currentTimeMillis.getAsLong();
                silentWaitMs = INITIAL_SILENT_WAIT_MS;
                silentWaitUntilNanos = nanoTime.getAsLong() + TimeUnit.MILLISECONDS.toNanos(silentWaitMs);
                smartPhase = SmartThrottlePhase.CALIBRATING_BURST;
                smartEpoch++; // Invalidate in-flight unlimited-mode responses
                safeLog(String.format("Smart throttle%s: unexpected throttle in unlimited mode, probing for reset in %ds.",
                    scopeSuffix(), silentWaitMs / 1000));
                notifyAll();
            }
            return;
        }

        if (isThrottle) {
            // Mid-burst 429: distinguish cooldown problem vs burst problem.
            // If very few requests succeeded relative to burst size, the cooldown
            // was too short (rate limit hadn't reset). If many succeeded, the burst
            // is genuinely too large.
            double successRatio = burstSize > 0 ? (double) burstSuccessCount / burstSize : 0;
            int prevBurst = burstSize;
            long prevCooldown = cooldownMs;

            if (successRatio < 0.3) {
                // Cooldown problem: rate limit hadn't reset. Increase cooldown,
                // keep burst at a reasonable fraction of the calibrated value.
                cooldownMs = Math.max(MIN_COOLDOWN_MS, (long) (cooldownMs * 1.5));
                burstSize = Math.max(1, calibratedBurstSize / 2);
                safeLog(String.format("Smart throttle%s: mid-burst 429 early (%d/%d succeeded, ratio %.0f%%) -- cooldown too short. "
                    + "cooldown %ds->%ds, burst %d->%d.",
                    scopeSuffix(), burstSuccessCount, prevBurst, successRatio * 100,
                    prevCooldown / 1000, cooldownMs / 1000, prevBurst, burstSize));
            } else {
                // Burst problem: too many requests before server can handle them.
                burstSize = Math.max(1, (int) (burstSuccessCount * 0.85));
                safeLog(String.format("Smart throttle%s: mid-burst 429 deep (%d/%d succeeded, ratio %.0f%%) -- burst too large. "
                    + "burst %d->%d.",
                    scopeSuffix(), burstSuccessCount, prevBurst, successRatio * 100,
                    prevBurst, burstSize));
            }

            firstThrottleMs = currentTimeMillis.getAsLong();
            probing = true;
            singleRequestInFlight = false;
            silentWaitMs = cooldownMs > 0 ? cooldownMs : INITIAL_SILENT_WAIT_MS;
            silentWaitUntilNanos = nanoTime.getAsLong() + TimeUnit.MILLISECONDS.toNanos(silentWaitMs);
            consecutiveCleanCycles = 0;
            burstSent = burstSize; // Forces burst exhaustion so no more permits are granted
            smartEpoch++; // Invalidate remaining in-flight burst responses
            notifyAll();
        } else {
            // Successful response during RUNNING -- track for accurate burst sizing
            burstSuccessCount++;
        }
    }

    /**
     * Called by the engine after a full burst completes cleanly (no throttle responses).
     * Tracks clean cycles and triggers adjustment when threshold is reached.
     */
    public synchronized void reportCleanBurst() {
        if (!smartThrottleEnabled || burstSize == 0) return;
        consecutiveCleanCycles++;
        if (consecutiveCleanCycles >= CLEAN_CYCLES_BEFORE_ADJUST && smartPhase == SmartThrottlePhase.RUNNING) {
            smartPhase = SmartThrottlePhase.ADJUSTING;
            int newBurst = Math.max(burstSize + 1, (int) (burstSize * 1.1));
            safeLog(String.format("Smart throttle%s: trying burst=%d (was %d).",
                scopeSuffix(), newBurst, burstSize));
            burstSize = newBurst;
            consecutiveCleanCycles = 0;
            smartPhase = SmartThrottlePhase.RUNNING;
            notifyAll();
        }
    }

    /**
     * Called when adjustment burst gets throttled -- reverts burst and increases cooldown.
     */
    public synchronized void revertAdjustment(int previousBurstSize) {
        if (!smartThrottleEnabled) return;
        burstSize = previousBurstSize;
        cooldownMs += 5000;
        safeLog(String.format("Smart throttle%s: adjustment failed, reverting burst=%d, cooldown=%ds.",
            scopeSuffix(), burstSize, cooldownMs / 1000));
        notifyAll();
    }

    /**
     * Called when adjustment succeeds -- try reducing cooldown.
     */
    public synchronized void adjustCooldownDown() {
        if (!smartThrottleEnabled || cooldownMs <= 1000) return;
        cooldownMs = Math.max(1000, (long) (cooldownMs * 0.9));
        safeLog(String.format("Smart throttle%s: cooldown reduced to %ds.",
            scopeSuffix(), cooldownMs / 1000));
        notifyAll();
    }

    private void recoverAfterSuccessfulResponse(long now) {
        if (adaptiveDelayMs <= 0 || now < nextRecoveryAdjustmentEpochMs) {
            return;
        }

        long previousDelay = adaptiveDelayMs;
        long reducedDelay = Math.max(0, adaptiveDelayMs / 2);
        if (adaptiveDelayFloorMs > 0) {
            reducedDelay = Math.max(reducedDelay, adaptiveDelayFloorMs);
        }
        if (reducedDelay >= adaptiveDelayMs) {
            return;
        }
        adaptiveDelayMs = (adaptiveDelayFloorMs > 0) ? reducedDelay
            : (reducedDelay <= baseDelayMs() ? 0 : reducedDelay);
        nextRecoveryAdjustmentEpochMs = adaptiveDelayMs == 0 ? 0 : now + recoveryWindowMs();
        notifyAll();
        if (adaptiveDelayFloorMs > 0 && adaptiveDelayMs <= adaptiveDelayFloorMs) {
            safeLog(String.format("Auto-throttle recovery%s: pacing stabilized at %d ms.",
                scopeSuffix(), effectiveDelayMs()));
        } else {
            safeLog(String.format("Auto-throttle recovery%s: pacing reduced from %d ms to %d ms.",
                scopeSuffix(), previousDelay, effectiveDelayMs()));
        }
    }

    private long recoveryWindowMs() {
        return Math.min(MAX_BACKOFF_MS, Math.max(MIN_RECOVERY_WINDOW_MS, adaptiveDelayMs * 2));
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

    synchronized long getRemainingWaitMs() {
        long scheduledWaitNanos = Math.max(0, nextRequestNanos - nanoTime.getAsLong());
        long retryAfterWaitMs = Math.max(0, blockedUntilEpochMs - currentTimeMillis.getAsLong());
        long scheduledWaitMs = TimeUnit.NANOSECONDS.toMillis(scheduledWaitNanos);
        return Math.max(scheduledWaitMs, retryAfterWaitMs);
    }

    // Smart throttle public API

    public void enableSmartThrottle(boolean enabled) {
        this.smartThrottleEnabled = enabled;
        if (enabled) {
            synchronized (this) {
                calibrating = true;
                probing = false;
                singleRequestInFlight = false;
                burstSent = 0;
                burstSuccessCount = 0;
                calibrationRequestCount = 0;
                calibrationSuccessCount = 0;
                burstSize = 0;
                calibratedBurstSize = 0;
                cooldownMs = 0;
                successBeforeThrottle = 0;
                consecutiveCleanCycles = 0;
                silentWaitMs = 0;
                silentWaitUntilNanos = 0;
                smartEpoch++;
                smartPhase = SmartThrottlePhase.CALIBRATING_BURST;
                safeLog(String.format("Smart throttle%s: enabled, starting calibration.", scopeSuffix()));
                notifyAll();
            }
        }
    }

    public boolean isSmartThrottleEnabled() {
        return smartThrottleEnabled;
    }

    public synchronized int getCalibratedBurstSize() {
        return burstSize;
    }

    public synchronized long getCalibratedCooldownMs() {
        return cooldownMs;
    }

    public synchronized String getSmartThrottleStatus() {
        if (!smartThrottleEnabled) return "Disabled";
        if (probing) return String.format("Waiting for reset (%ds silent wait)...", silentWaitMs / 1000);
        if (calibrating) return "Calibrating...";
        if (burstSize == 0) return "No rate limit detected";
        return String.format("Burst %d, cooldown %ds", burstSize, cooldownMs / 1000);
    }

    public boolean isThrottleStatusCode(int statusCode) {
        return throttleStatusCodes.contains(statusCode);
    }

    public void enqueueForRetry(ThrottledRequest request) {
        if (retryQueue.size() < MAX_RETRY_QUEUE_SIZE) {
            retryQueue.add(request);
        }
    }

    public List<ThrottledRequest> drainRetryQueue(int maxCount) {
        List<ThrottledRequest> drained = new ArrayList<>();
        for (int i = 0; i < maxCount; i++) {
            ThrottledRequest req = retryQueue.poll();
            if (req == null) break;
            drained.add(req);
        }
        return drained;
    }

    public int getRetryQueueSize() {
        return retryQueue.size();
    }

    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }

    private String scopeSuffix() {
        return scopeLabel.isBlank() ? "" : " [" + scopeLabel + "]";
    }
}
