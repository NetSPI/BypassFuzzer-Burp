package com.bypassfuzzer.burp.core.idor;

import java.util.Set;

/**
 * Execution options for a single IDOR/BOLA run.
 */
public record IdorRunOptions(
    int requestsPerSecond,
    int requestDelayMs,
    Set<Integer> throttleStatusCodes,
    boolean autoThrottleEnabled
) {
    public IdorRunOptions(int requestsPerSecond, int requestDelayMs, Set<Integer> throttleStatusCodes) {
        this(requestsPerSecond, requestDelayMs, throttleStatusCodes,
            throttleStatusCodes != null && !throttleStatusCodes.isEmpty());
    }

    public IdorRunOptions(int requestsPerSecond, Set<Integer> throttleStatusCodes) {
        this(requestsPerSecond, 0, throttleStatusCodes,
            throttleStatusCodes != null && !throttleStatusCodes.isEmpty());
    }
}
