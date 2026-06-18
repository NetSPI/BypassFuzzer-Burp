package com.bypassfuzzer.burp.core.coverage;

import java.util.Set;

public record CoverageSweepOptions(
    Set<Integer> statuses,
    boolean inScopeOnly,
    int maxCandidates,
    int maxProbesPerCandidate,
    int requestsPerSecond,
    Set<Integer> throttleStatusCodes
) {

    public static CoverageSweepOptions defaults() {
        return new CoverageSweepOptions(
            Set.of(401, 403),
            true,
            100,
            30,
            0,
            Set.of(429, 503)
        );
    }
}
