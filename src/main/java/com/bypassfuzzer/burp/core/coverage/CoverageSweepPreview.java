package com.bypassfuzzer.burp.core.coverage;

import java.util.List;
import java.util.Set;

public record CoverageSweepPreview(
    int blockedHistoryCount,
    int dedupedEndpointCount,
    List<CoverageSweepCandidate> candidates,
    Set<String> discoveredHeaderNames,
    Set<String> discoveredCookieNames
) {

    public CoverageSweepPreview(int blockedHistoryCount, int dedupedEndpointCount,
                                List<CoverageSweepCandidate> candidates) {
        this(blockedHistoryCount, dedupedEndpointCount, candidates, Set.of(), Set.of());
    }

    public int selectedCandidateCount() {
        return candidates.size();
    }
}
