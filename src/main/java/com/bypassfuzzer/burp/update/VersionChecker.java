package com.bypassfuzzer.burp.update;

import burp.api.montoya.MontoyaApi;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public class VersionChecker {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final BuildInfo buildInfo;
    private final ManifestFetcher manifestFetcher;

    public VersionChecker(BuildInfo buildInfo) {
        this(buildInfo, VersionChecker::fetchManifest);
    }

    VersionChecker(BuildInfo buildInfo, ManifestFetcher manifestFetcher) {
        this.buildInfo = buildInfo;
        this.manifestFetcher = manifestFetcher;
    }

    public static void checkAsync(MontoyaApi api) {
        BuildInfo buildInfo = BuildInfo.load();
        logOutput(api, "BypassFuzzer version " + buildInfo.version() + " loaded");

        if (!buildInfo.hasUpdateManifestUrl()) {
            logOutput(api, "BypassFuzzer update check disabled: no update manifest URL embedded");
            return;
        }

        Thread checkerThread = new Thread(() -> {
            try {
                VersionCheckResult result = new VersionChecker(buildInfo).check();
                if (result.updateAvailable()) {
                    logOutput(api, "BypassFuzzer update available: " + result.latestVersion()
                        + " (current " + result.currentVersion() + ")");
                    showUpdatePopup(api, result);
                } else {
                    logOutput(api, "BypassFuzzer is up to date (" + result.currentVersion() + ")");
                }
            } catch (Exception e) {
                logError(api, "BypassFuzzer update check failed: " + e.getMessage());
            }
        }, "bypassfuzzer-version-check");
        checkerThread.setDaemon(true);
        checkerThread.start();
    }

    public VersionCheckResult check() throws Exception {
        if (!buildInfo.hasUpdateManifestUrl()) {
            return new VersionCheckResult(buildInfo.version(), "", false);
        }

        String latestVersion = firstLine(manifestFetcher.fetch(URI.create(buildInfo.updateManifestUrl())));
        return new VersionCheckResult(
            buildInfo.version(),
            latestVersion,
            compareVersions(latestVersion, buildInfo.version()) > 0
        );
    }

    public static int compareVersions(String left, String right) {
        String[] leftParts = normalizeVersion(left).split("\\.");
        String[] rightParts = normalizeVersion(right).split("\\.");
        int length = Math.max(leftParts.length, rightParts.length);
        for (int index = 0; index < length; index++) {
            int leftValue = numericPart(leftParts, index);
            int rightValue = numericPart(rightParts, index);
            if (leftValue != rightValue) {
                return Integer.compare(leftValue, rightValue);
            }
        }
        return 0;
    }

    private static String fetchManifest(URI uri) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
        HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(REQUEST_TIMEOUT)
            .header("Cache-Control", "no-cache")
            .GET()
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("manifest returned HTTP " + response.statusCode());
        }
        return response.body();
    }

    private static String firstLine(String body) {
        if (body == null) {
            return "";
        }
        String[] lines = body.strip().split("\\R", 2);
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private static String normalizeVersion(String version) {
        if (version == null) {
            return "0";
        }
        String normalized = version.trim();
        if (normalized.startsWith("v") || normalized.startsWith("V")) {
            normalized = normalized.substring(1);
        }
        return normalized.isBlank() ? "0" : normalized;
    }

    private static int numericPart(String[] parts, int index) {
        if (index >= parts.length) {
            return 0;
        }
        String part = parts[index].replaceFirst("[^0-9].*$", "");
        if (part.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(part);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void logOutput(MontoyaApi api, String message) {
        try {
            api.logging().logToOutput(message);
        } catch (Exception e) {
            // Ignore logging failures during load/unload races.
        }
    }

    private static void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {
            // Ignore logging failures during load/unload races.
        }
    }

    private static void showUpdatePopup(MontoyaApi api, VersionCheckResult result) {
        SwingUtilities.invokeLater(() -> {
            try {
                JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    updateMessage(result),
                    "BypassFuzzer Update Available",
                    JOptionPane.INFORMATION_MESSAGE
                );
            } catch (Exception e) {
                logError(api, "BypassFuzzer update popup failed: " + e.getMessage());
            }
        });
    }

    static String updateMessage(VersionCheckResult result) {
        return "A new BypassFuzzer release is available.\n\n"
            + "Current version: " + result.currentVersion() + "\n"
            + "Latest version: " + result.latestVersion() + "\n\n"
            + "Download the latest bypassfuzzer.jar from the GitHub releases page.";
    }

    @FunctionalInterface
    interface ManifestFetcher {
        String fetch(URI uri) throws Exception;
    }
}
