package com.bypassfuzzer.burp.update;

import java.io.InputStream;
import java.util.Properties;

public record BuildInfo(String version, String updateManifestUrl, String devLatestVersion) {

    private static final String RESOURCE_NAME = "/bypassfuzzer-build.properties";

    public static BuildInfo load() {
        Properties properties = new Properties();
        try (InputStream stream = BuildInfo.class.getResourceAsStream(RESOURCE_NAME)) {
            if (stream != null) {
                properties.load(stream);
            }
        } catch (Exception e) {
            // Fall through to defaults; version checking should never block extension load.
        }

        return new BuildInfo(
            valueOrDefault(properties.getProperty("version"), "dev"),
            valueOrDefault(properties.getProperty("updateManifestUrl"), ""),
            valueOrDefault(properties.getProperty("devLatestVersion"), "")
        );
    }

    public boolean hasUpdateManifestUrl() {
        return updateManifestUrl != null && !updateManifestUrl.isBlank();
    }

    public boolean hasDevLatestVersion() {
        return devLatestVersion != null && !devLatestVersion.isBlank();
    }

    private static String valueOrDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
