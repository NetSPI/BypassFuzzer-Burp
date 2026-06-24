package com.bypassfuzzer.burp.update;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionCheckerTest {

    @Test
    void comparesSemanticVersionsWithOptionalVPrefix() {
        assertTrue(VersionChecker.compareVersions("1.0.10", "1.0.9") > 0);
        assertTrue(VersionChecker.compareVersions("v1.2.0", "1.1.9") > 0);
        assertEquals(0, VersionChecker.compareVersions("1.0.9", "1.0.9"));
        assertTrue(VersionChecker.compareVersions("1.0.8", "1.0.9") < 0);
    }

    @Test
    void reportsUpdateAvailableFromManifest() throws Exception {
        VersionChecker checker = new VersionChecker(
            new BuildInfo("1.0.9", "https://example.test/bypassfuzzer_version.txt"),
            uri -> "1.0.10\n"
        );

        VersionCheckResult result = checker.check();

        assertEquals("1.0.9", result.currentVersion());
        assertEquals("1.0.10", result.latestVersion());
        assertTrue(result.updateAvailable());
    }

    @Test
    void disabledWhenManifestUrlIsBlank() throws Exception {
        VersionChecker checker = new VersionChecker(
            new BuildInfo("1.0.9", ""),
            uri -> {
                throw new AssertionError("Fetcher should not run without a manifest URL");
            }
        );

        VersionCheckResult result = checker.check();

        assertEquals("1.0.9", result.currentVersion());
        assertFalse(result.updateAvailable());
    }
}
