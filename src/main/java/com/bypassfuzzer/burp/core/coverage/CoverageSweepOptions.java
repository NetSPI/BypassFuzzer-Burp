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
    Set<Integer> throttleStatusCodes,
    CoverageSweepMode mode,
    CoverageSweepAuthSelection authSelection,
    boolean excludeStaticAssets,
    boolean verifyUnauthenticatedAccess,
    boolean doublePortHostProbes,
    boolean autoThrottleEnabled
) {

    public CoverageSweepOptions {
        mode = mode == null ? CoverageSweepMode.BLOCKED_RESPONSES : mode;
        authSelection = authSelection == null ? CoverageSweepAuthSelection.defaults() : authSelection;
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                int requestDelayMs, Set<Integer> throttleStatusCodes,
                                CoverageSweepMode mode, CoverageSweepAuthSelection authSelection,
                                boolean excludeStaticAssets, boolean verifyUnauthenticatedAccess,
                                boolean doublePortHostProbes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, requestDelayMs, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, verifyUnauthenticatedAccess, doublePortHostProbes,
            throttleStatusCodes != null && !throttleStatusCodes.isEmpty());
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                Set<Integer> throttleStatusCodes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, 0, throttleStatusCodes, CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(), true, false, false);
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                int requestDelayMs, Set<Integer> throttleStatusCodes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, requestDelayMs, throttleStatusCodes, CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(), true, false, false);
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                int requestDelayMs, Set<Integer> throttleStatusCodes,
                                CoverageSweepMode mode, CoverageSweepAuthSelection authSelection) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, requestDelayMs, throttleStatusCodes, mode, authSelection, true);
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                int requestDelayMs, Set<Integer> throttleStatusCodes,
                                CoverageSweepMode mode, CoverageSweepAuthSelection authSelection,
                                boolean excludeStaticAssets) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, requestDelayMs, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, false, false);
    }

    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int requestsPerSecond,
                                int requestDelayMs, Set<Integer> throttleStatusCodes,
                                CoverageSweepMode mode, CoverageSweepAuthSelection authSelection,
                                boolean excludeStaticAssets, boolean verifyUnauthenticatedAccess) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            requestsPerSecond, requestDelayMs, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, verifyUnauthenticatedAccess, false);
    }

    public static CoverageSweepOptions defaults() {
        return new CoverageSweepOptions(
            Set.of(401, 403),
            true,
            100,
            280,
            1,
            0,
            0,
            Set.of(429, 503),
            CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(),
            true,
            true,
            false,
            true
        );
    }

    public CoverageSweepOptions withAuthenticatedTraffic(CoverageSweepAuthSelection selection) {
        return new CoverageSweepOptions(Set.of(), inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, requestsPerSecond, requestDelayMs, throttleStatusCodes,
            CoverageSweepMode.AUTHENTICATED_TRAFFIC, selection, excludeStaticAssets,
            verifyUnauthenticatedAccess, doublePortHostProbes, autoThrottleEnabled);
    }

    public CoverageSweepOptions withDoublePortHostProbes(boolean enabled) {
        return new CoverageSweepOptions(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, requestsPerSecond, requestDelayMs, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, verifyUnauthenticatedAccess, enabled, autoThrottleEnabled);
    }
}
