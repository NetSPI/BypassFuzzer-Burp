package com.bypassfuzzer.burp.core.coverage;

import java.util.List;

public record CoverageSweepPreview(
    int blockedHistoryCount,
    int dedupedEndpointCount,
    List<CoverageSweepCandidate> candidates
) {

    public int selectedCandidateCount() {
        return candidates.size();
    }
}
