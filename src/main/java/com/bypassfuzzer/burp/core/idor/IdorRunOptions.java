package com.bypassfuzzer.burp.core.idor;

import java.util.Set;

/**
 * Execution options for a single IDOR/BOLA run.
 */
public record IdorRunOptions(
    int requestsPerSecond,
    int requestDelayMs,
    Set<Integer> throttleStatusCodes
) {
    public IdorRunOptions(int requestsPerSecond, Set<Integer> throttleStatusCodes) {
        this(requestsPerSecond, 0, throttleStatusCodes);
    }
}
