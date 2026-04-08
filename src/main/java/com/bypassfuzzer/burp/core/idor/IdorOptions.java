package com.bypassfuzzer.burp.core.idor;

/**
 * User-supplied IDOR analysis settings for a single run.
 */
public record IdorOptions(
    String authorizedIdentifier,
    String targetIdentifier,
    IdorRunOptions runOptions
) {

    public String normalizedAuthorizedIdentifier() {
        return authorizedIdentifier == null ? "" : authorizedIdentifier.trim();
    }

    public String normalizedTargetIdentifier() {
        return targetIdentifier == null ? "" : targetIdentifier.trim();
    }
}
