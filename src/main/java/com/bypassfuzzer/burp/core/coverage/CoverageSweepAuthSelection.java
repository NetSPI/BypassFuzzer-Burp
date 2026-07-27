package com.bypassfuzzer.burp.core.coverage;

import java.util.Set;

public record CoverageSweepAuthSelection(
    Set<String> headerNames,
    Set<String> cookieNames,
    boolean includeUnsafeMethods
) {
    public CoverageSweepAuthSelection {
        headerNames = headerNames == null ? Set.of() : Set.copyOf(headerNames);
        cookieNames = cookieNames == null ? Set.of() : Set.copyOf(cookieNames);
    }

    public static CoverageSweepAuthSelection defaults() {
        return new CoverageSweepAuthSelection(Set.of("Authorization"), Set.of(), false);
    }
}
