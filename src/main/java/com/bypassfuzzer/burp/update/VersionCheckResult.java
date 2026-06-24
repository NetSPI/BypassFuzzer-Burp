package com.bypassfuzzer.burp.update;

public record VersionCheckResult(
    String currentVersion,
    String latestVersion,
    boolean updateAvailable
) {
}
