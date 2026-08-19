package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;

import java.util.Set;

/**
 * Default values and feature visibility for the shared throttle settings dialog.
 *
 * @param concurrency          initial concurrency value; -1 = don't show the field
 * @param perHostConcurrency   initial per-host concurrency; -1 = don't show the field
 * @param requestsPerSecond    initial RPS value; -1 = don't show the field
 * @param requestDelayMs       initial delay between requests
 * @param throttleStatusCodes  initial throttle status codes
 * @param autoThrottle         initial auto-throttle checkbox state
 * @param smartThrottle        initial smart-throttle checkbox state
 * @param concurrencyLabel     label for the concurrency field ("Concurrency" vs "Global concurrency")
 */
public record ThrottleDefaults(
    int concurrency,
    int perHostConcurrency,
    int requestsPerSecond,
    int requestDelayMs,
    Set<Integer> throttleStatusCodes,
    boolean autoThrottle,
    boolean smartThrottle,
    String concurrencyLabel
) {

    static ThrottleDefaults forBypassFuzzer(FuzzerConfig config) {
        return new ThrottleDefaults(
            config.getConcurrency(),
            -1,
            -1,
            config.getRequestDelayMs(),
            config.getThrottleStatusCodes(),
            config.isEnableAutoThrottle(),
            config.isSmartThrottleEnabled(),
            "Concurrency"
        );
    }

    static ThrottleDefaults forCoverageSweep(CoverageSweepOptions defaults) {
        return new ThrottleDefaults(
            defaults.concurrency(),
            defaults.perHostConcurrency(),
            -1,
            defaults.requestDelayMs(),
            defaults.throttleStatusCodes(),
            defaults.autoThrottleEnabled(),
            defaults.smartThrottleEnabled(),
            "Global concurrency"
        );
    }

    static ThrottleDefaults forIdor(IdorRunOptions defaults) {
        return new ThrottleDefaults(
            -1,
            -1,
            defaults.requestsPerSecond(),
            defaults.requestDelayMs(),
            defaults.throttleStatusCodes(),
            defaults.autoThrottleEnabled(),
            false,
            "Concurrency"
        );
    }

    static ThrottleDefaults forUrlValidation() {
        return new ThrottleDefaults(
            -1,
            -1,
            0,
            0,
            Set.of(429, 503),
            true,
            false,
            "Concurrency"
        );
    }
}
