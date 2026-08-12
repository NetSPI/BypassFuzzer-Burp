package com.bypassfuzzer.burp.core.idor;

import com.bypassfuzzer.burp.http.ConfiguredHeader;

import java.util.List;
import java.util.Set;

/**
 * Execution options for a single IDOR/BOLA run.
 */
public record IdorRunOptions(
    int requestsPerSecond,
    int requestDelayMs,
    Set<Integer> throttleStatusCodes,
    boolean autoThrottleEnabled,
    List<ConfiguredHeader> requestHeaders
) {
    public IdorRunOptions {
        requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
    }

    public IdorRunOptions(int requestsPerSecond, int requestDelayMs, Set<Integer> throttleStatusCodes,
                          boolean autoThrottleEnabled) {
        this(requestsPerSecond, requestDelayMs, throttleStatusCodes, autoThrottleEnabled,
            List.of());
    }

    public IdorRunOptions(int requestsPerSecond, int requestDelayMs, Set<Integer> throttleStatusCodes) {
        this(requestsPerSecond, requestDelayMs, throttleStatusCodes,
            throttleStatusCodes != null && !throttleStatusCodes.isEmpty(), List.of());
    }

    public IdorRunOptions(int requestsPerSecond, Set<Integer> throttleStatusCodes) {
        this(requestsPerSecond, 0, throttleStatusCodes,
            throttleStatusCodes != null && !throttleStatusCodes.isEmpty(), List.of());
    }
}
