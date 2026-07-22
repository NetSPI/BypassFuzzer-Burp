package com.bypassfuzzer.burp.core.coverage;

import java.util.Set;

public record CoverageSweepOptions(
    Set<Integer> statuses,
    boolean inScopeOnly,
    int maxCandidates,
    int maxProbesPerCandidate,
    int concurrency,
    int requestsPerSecond,
    int requestDelayMs,
    Set<Integer> throttleStatusCodes
) {

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                Set<Integer> throttleStatusCodes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, 0, throttleStatusCodes);
    }

    public static CoverageSweepOptions defaults() {
        return new CoverageSweepOptions(
            Set.of(401, 403),
            true,
            100,
            120,
            1,
            0,
            0,
            Set.of(429, 503)
        );
    }
}
