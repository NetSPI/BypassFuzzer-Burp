package com.bypassfuzzer.burp.core.urlvalidation;

import java.util.Set;

public record UrlValidationOptions(
    String markerText,
    String allowedHost,
    String attackerHost,
    boolean collaboratorPayloads,
    String attackerScheme,
    Set<UrlValidationContext> payloadFamilies,
    Set<UrlValidationAttackSetting> attackSettings,
    UrlValidationEncoding encoding,
    int requestsPerSecond,
    Set<Integer> throttleStatusCodes
) {

    private static final Set<UrlValidationContext> DEFAULT_PAYLOAD_FAMILIES = Set.of(
        UrlValidationContext.ABSOLUTE_URL,
        UrlValidationContext.HOSTNAME
    );
    private static final Set<UrlValidationAttackSetting> DEFAULT_ATTACK_SETTINGS = Set.of(
        UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
        UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
        UrlValidationAttackSetting.LOOPBACK
    );

    public String normalizedAllowedHost() {
        return normalizeHost(allowedHost);
    }

    public String normalizedAttackerHost() {
        return normalizeHost(attackerHost);
    }

    public boolean useCollaboratorPayloads() {
        return collaboratorPayloads;
    }

    public String normalizedAttackerScheme() {
        if (attackerScheme == null || attackerScheme.isBlank()) {
            return "https";
        }
        return attackerScheme.trim().toLowerCase();
    }

    public Set<UrlValidationContext> normalizedPayloadFamilies() {
        return payloadFamilies == null ? DEFAULT_PAYLOAD_FAMILIES : Set.copyOf(payloadFamilies);
    }

    public Set<UrlValidationAttackSetting> normalizedAttackSettings() {
        return attackSettings == null ? DEFAULT_ATTACK_SETTINGS : Set.copyOf(attackSettings);
    }

    public UrlValidationEncoding effectiveEncoding() {
        return encoding == null ? UrlValidationEncoding.RAW : encoding;
    }

    public String normalizedMarkerText() {
        if (markerText == null || markerText.isBlank()) {
            return "{INJECT}";
        }
        return markerText.trim();
    }

    private String normalizeHost(String value) {
        if (value == null) {
            return "";
        }

        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return "";
        }

        String normalized = trimmed.replaceFirst("^https?://", "");
        int slashIndex = normalized.indexOf('/');
        if (slashIndex >= 0) {
            normalized = normalized.substring(0, slashIndex);
        }
        return normalized;
    }
}
