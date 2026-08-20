package com.bypassfuzzer.burp.core.idor;

import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

import java.util.List;
import java.util.Set;

/**
 * Execution options for a single IDOR/BOLA run.
 */
public record IdorRunOptions(
    Set<Integer> throttleStatusCodes,
    ThrottleSettings.Posture posture,
    List<ConfiguredHeader> requestHeaders
) {
    public IdorRunOptions {
        posture = posture == null ? ThrottleSettings.Posture.RIDE_HARD : posture;
        requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
    }

    public IdorRunOptions(Set<Integer> throttleStatusCodes) {
        this(throttleStatusCodes, ThrottleSettings.Posture.RIDE_HARD, List.of());
    }

    public IdorRunOptions(Set<Integer> throttleStatusCodes, List<ConfiguredHeader> requestHeaders) {
        this(throttleStatusCodes, ThrottleSettings.Posture.RIDE_HARD, requestHeaders);
    }

    /** Alias for {@link #posture()} used by the shared throttle-settings defaults. */
    public ThrottleSettings.Posture throttlePosture() {
        return posture;
    }

    /** Adaptive per-host throttle configuration; IDOR playbooks run serially. */
    public ThrottleSettings throttleSettings() {
        return new ThrottleSettings(throttleStatusCodes, 1, 1, 400.0, posture);
    }
}
