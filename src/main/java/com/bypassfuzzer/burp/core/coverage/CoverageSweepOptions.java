package com.bypassfuzzer.burp.core.coverage;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

import java.util.List;
import java.util.Set;

public record CoverageSweepOptions(
    Set<Integer> statuses,
    boolean inScopeOnly,
    int maxCandidates,
    int maxProbesPerCandidate,
    int concurrency,
    int perHostConcurrency,
    Set<Integer> throttleStatusCodes,
    CoverageSweepMode mode,
    CoverageSweepAuthSelection authSelection,
    boolean excludeStaticAssets,
    boolean verifyUnauthenticatedAccess,
    List<Integer> hostPortProbePorts,
    List<ConfiguredHeader> requestHeaders,
    CoverageSweepPayloadSet payloadSet,
    ThrottleSettings.Posture posture
) {

    public CoverageSweepOptions {
        mode = mode == null ? CoverageSweepMode.BLOCKED_RESPONSES : mode;
        authSelection = authSelection == null ? CoverageSweepAuthSelection.defaults() : authSelection;
        hostPortProbePorts = hostPortProbePorts == null ? List.of() : List.copyOf(hostPortProbePorts);
        requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
        payloadSet = payloadSet == null ? CoverageSweepPayloadSet.HIGH_SIGNAL : payloadSet;
        posture = posture == null ? ThrottleSettings.Posture.RIDE_HARD : posture;
        perHostConcurrency = Math.max(1, perHostConcurrency);
    }

    /** Alias for {@link #posture()} used by the shared throttle-settings defaults. */
    public ThrottleSettings.Posture throttlePosture() {
        return posture;
    }

    public boolean hostPortProbesEnabled() {
        return !hostPortProbePorts.isEmpty();
    }

    /** Convenience: blocked-response defaults with explicit concurrency and throttle codes. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(), true, false, List.of(), List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth selection. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, true, false, List.of(),
            List.of(), CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth + static-asset / unauthenticated toggles. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, List.of(), List.of(), CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /** Convenience: adds mode + auth + toggles + host-port probe ports. */
    public CoverageSweepOptions(Set<Integer> statuses, boolean inScopeOnly, int maxCandidates,
                                int maxProbesPerCandidate, int concurrency, int perHostConcurrency,
                                Set<Integer> throttleStatusCodes, CoverageSweepMode mode,
                                CoverageSweepAuthSelection authSelection, boolean excludeStaticAssets,
                                boolean verifyUnauthenticatedAccess, List<Integer> hostPortProbePorts) {
        this(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate, concurrency,
            perHostConcurrency, throttleStatusCodes, mode, authSelection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL, ThrottleSettings.Posture.RIDE_HARD);
    }

    /**
     * The adaptive-throttle configuration for this run. Pacing is handled per host by the adaptive
     * controller, so the concurrency fields become in-flight resource caps rather than rate knobs;
     * they are floored high enough to let the controller saturate every host up to its discovered
     * ceiling.
     */
    public ThrottleSettings throttleSettings() {
        int global = Math.max(50, concurrency);
        int perHost = Math.max(50, perHostConcurrency);
        return new ThrottleSettings(throttleStatusCodes, global, perHost, 400.0, posture);
    }

    public static CoverageSweepOptions defaults() {
        return new CoverageSweepOptions(
            Set.of(401, 403),
            true,
            100,
            280,
            1,
            1,
            Set.of(429, 503),
            CoverageSweepMode.BLOCKED_RESPONSES,
            CoverageSweepAuthSelection.defaults(),
            true,
            true,
            List.of(),
            List.of(),
            CoverageSweepPayloadSet.HIGH_SIGNAL,
            ThrottleSettings.Posture.RIDE_HARD
        );
    }

    public CoverageSweepOptions withAuthenticatedTraffic(CoverageSweepAuthSelection selection) {
        return new CoverageSweepOptions(Set.of(), inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, perHostConcurrency, throttleStatusCodes,
            CoverageSweepMode.AUTHENTICATED_TRAFFIC, selection, excludeStaticAssets,
            verifyUnauthenticatedAccess, hostPortProbePorts, requestHeaders, payloadSet, posture);
    }

    public CoverageSweepOptions withHostPortProbePorts(List<Integer> ports) {
        return new CoverageSweepOptions(statuses, inScopeOnly, maxCandidates, maxProbesPerCandidate,
            concurrency, perHostConcurrency, throttleStatusCodes, mode, authSelection,
            excludeStaticAssets, verifyUnauthenticatedAccess, ports, requestHeaders, payloadSet, posture);
    }
}
