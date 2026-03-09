package com.bypassfuzzer.burp.core.urlvalidation;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Generates URL validation payloads from bundled PortSwigger source wordlists.
 */
public class UrlValidationPayloadGenerator {

    private static final String RENDERED_RESOURCE = "/payloads/url_validation_cheatsheet.json";
    private static final String SOURCE_RESOURCE = "/payloads/url_validation_source_data.json";
    private static final String DEFAULT_ALLOWED_HOST = "example.com";
    private static final String DEFAULT_RENDERED_ALLOWED_HOST = "example.com";
    private static final String DEFAULT_RENDERED_ATTACKER_HOST = "web-attacker.com";
    private static final String CATEGORY = "CHEATSHEET";
    private static final Type RESOURCE_TYPE = new TypeToken<List<SourceWordlist>>() {
    }.getType();
    private static final Type RENDERED_RESOURCE_TYPE = new TypeToken<Map<String, Map<String, List<String>>>>() {
    }.getType();
    private static final Map<UrlValidationAttackSetting, List<SourcePayload>> WORDLISTS = loadWordlists();
    private static final Map<String, Map<String, List<String>>> RENDERED_PAYLOADS = loadRenderedPayloads();
    private static final Set<UrlValidationAttackSetting> DEFAULT_RENDERED_ATTACK_SETTINGS = Set.of(
        UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
        UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
        UrlValidationAttackSetting.LOOPBACK
    );
    private static final Set<String> CORS_EXCLUDED_SOURCE_IDS = Set.of(
        "774d39681f93dd129c28e19122be14831684a1ae",
        "f290a8f3c04e67ee70722ae1e0d0a821a1b74408",
        "363d6e8b3bc70faf9bf55367f127ff502fb3f429",
        "8d52c4fcf76fa2e662a3df7903653189af480967",
        "715a06de30c2c88c39fe5e586cb906d436940a40",
        "97cef03a53eb5bd597deb2eb703e419eb2e70aa1",
        "cfa39a4008237a7be563114230f1aa624ce0c46c",
        "18a114b8a46c2f257d2a84cd3a9ef7d85966cf03",
        "6144ab11463cbf6c4346ecfb5aebf2e135e89984",
        "aa2b6caa1bc125a1617a779bf35faf2a7ea71114"
    );

    public List<UrlValidationPayload> generate(UrlValidationCandidate candidate, UrlValidationOptions options) {
        String allowedHost = preferredAllowedHost(candidate, options);
        String attackerHost = options.normalizedAttackerHost();
        UrlValidationEncoding encoding = options.effectiveEncoding();
        String scheme = options.normalizedAttackerScheme();
        List<UrlValidationPayload> payloads = new ArrayList<>();
        Set<UrlValidationAttackSetting> selectedSettings = options.normalizedAttackSettings();

        if (selectedSettings.containsAll(DEFAULT_RENDERED_ATTACK_SETTINGS)) {
            addRenderedDefaultPayloads(payloads, options, allowedHost, attackerHost);
            selectedSettings = selectedSettings.stream()
                .filter(setting -> !DEFAULT_RENDERED_ATTACK_SETTINGS.contains(setting))
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        }

        for (UrlValidationAttackSetting attackSetting : selectedSettings) {
            List<SourcePayload> sourcePayloads = WORDLISTS.getOrDefault(attackSetting, List.of());
            for (SourcePayload sourcePayload : sourcePayloads) {
                for (UrlValidationContext family : options.normalizedPayloadFamilies()) {
                    if (!sourcePayload.supports(family)) {
                        continue;
                    }
                    if (family == UrlValidationContext.CORS_ORIGIN && CORS_EXCLUDED_SOURCE_IDS.contains(sourcePayload.id())) {
                        continue;
                    }
                    String value = renderPayload(sourcePayload, family, scheme, allowedHost, attackerHost);
                    payloads.add(new UrlValidationPayload(family, CATEGORY, encoding, encode(value, encoding)));
                }
            }
        }

        return payloads;
    }

    private void addRenderedDefaultPayloads(List<UrlValidationPayload> payloads,
                                            UrlValidationOptions options,
                                            String allowedHost,
                                            String attackerHost) {
        String encodingKey = renderedEncodingKey(options.effectiveEncoding());
        for (UrlValidationContext family : options.normalizedPayloadFamilies()) {
            List<String> renderedValues = RENDERED_PAYLOADS
                .getOrDefault(renderedFamilyKey(family), Map.of())
                .getOrDefault(encodingKey, List.of());
            for (String renderedValue : renderedValues) {
                payloads.add(new UrlValidationPayload(
                    family,
                    CATEGORY,
                    options.effectiveEncoding(),
                    renderedValue
                        .replace(DEFAULT_RENDERED_ALLOWED_HOST, allowedHost)
                        .replace(DEFAULT_RENDERED_ATTACKER_HOST, attackerHost)
                ));
            }
        }
    }

    private String renderPayload(SourcePayload sourcePayload,
                                 UrlValidationContext family,
                                 String scheme,
                                 String allowedHost,
                                 String attackerHost) {
        String prefix = normalizeComponent(sourcePayload.prefix());
        String suffix = normalizeComponent(sourcePayload.suffix());
        String payload = sourcePayload.payload()
            .replace("<attacker>", attackerHost)
            .replace("<allowed>", allowedHost);

        String port = sourcePayload.port() == null ? "" : ":" + sourcePayload.port();
        if (prefix.isEmpty() && family != UrlValidationContext.HOSTNAME && !"null".equals(payload)) {
            prefix = scheme + "://";
        }

        return prefix + payload + port + suffix;
    }

    private String normalizeComponent(String value) {
        return value == null ? "" : value;
    }

    private String preferredAllowedHost(UrlValidationCandidate candidate, UrlValidationOptions options) {
        String configured = options.normalizedAllowedHost();
        if (!configured.isEmpty()) {
            return configured;
        }

        String extracted = extractHost(candidate.originalValue());
        return extracted.isEmpty() ? DEFAULT_ALLOWED_HOST : extracted;
    }

    private String extractHost(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }

        String trimmed = value.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                return uri.getHost() == null ? "" : uri.getHost();
            } catch (IllegalArgumentException e) {
                return "";
            }
        }

        if (trimmed.startsWith("//")) {
            String withoutSlashes = trimmed.substring(2);
            int slashIndex = withoutSlashes.indexOf('/');
            return slashIndex >= 0 ? withoutSlashes.substring(0, slashIndex) : withoutSlashes;
        }

        return trimmed.contains("/") ? "" : trimmed;
    }

    private String renderedFamilyKey(UrlValidationContext family) {
        return switch (family) {
            case ABSOLUTE_URL -> "Absolute URL";
            case HOSTNAME -> "Host header";
            case CORS_ORIGIN -> "CORS";
        };
    }

    private String renderedEncodingKey(UrlValidationEncoding encoding) {
        return switch (encoding) {
            case RAW -> "raw";
            case INTRUDERS -> "intruders";
            case EVERYTHING -> "everything";
            case SPECIAL_CHARS -> "special_chars";
            case UNICODE_ESCAPE -> "unicode_escape";
        };
    }

    private String encode(String value, UrlValidationEncoding encoding) {
        return switch (encoding) {
            case RAW -> value;
            case INTRUDERS -> percentEncodeSelective(value, ":/?#[]!$&'()*+,;=-._~\\");
            case EVERYTHING -> percentEncode(value, true);
            case SPECIAL_CHARS -> percentEncodeSelective(value, ":/?#[]@!$&'()*+,;=-._~\\");
            case UNICODE_ESCAPE -> unicodeEscape(value);
        };
    }

    private String percentEncode(String value, boolean encodeAlphaNumeric) {
        StringBuilder encoded = new StringBuilder();
        for (byte current : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = current & 0xff;
            char character = (char) unsigned;
            boolean alphaNumeric = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9');

            if (!encodeAlphaNumeric && alphaNumeric) {
                encoded.append(character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit((unsigned >> 4) & 0xf, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(unsigned & 0xf, 16)));
            }
        }
        return encoded.toString();
    }

    private String percentEncodeSelective(String value, String safeCharacters) {
        StringBuilder encoded = new StringBuilder();
        for (byte current : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = current & 0xff;
            char character = (char) unsigned;
            boolean alphaNumeric = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9');

            if (alphaNumeric || safeCharacters.indexOf(character) >= 0) {
                encoded.append(character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit((unsigned >> 4) & 0xf, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(unsigned & 0xf, 16)));
            }
        }
        return encoded.toString();
    }

    private String unicodeEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        for (char current : value.toCharArray()) {
            switch (current) {
                case '\t' -> escaped.append("\\t");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                default -> {
                    if (current < 0x20 || current > 0x7e) {
                        escaped.append(String.format("\\u%04X", (int) current));
                    } else {
                        escaped.append(current);
                    }
                }
            }
        }
        return escaped.toString();
    }

    private static Map<UrlValidationAttackSetting, List<SourcePayload>> loadWordlists() {
        InputStream inputStream = UrlValidationPayloadGenerator.class.getResourceAsStream(SOURCE_RESOURCE);
        if (inputStream == null) {
            throw new IllegalStateException("Missing URL validation source payload resource: " + SOURCE_RESOURCE);
        }

        try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            List<SourceWordlist> wordlists = new Gson().fromJson(reader, RESOURCE_TYPE);
            Map<UrlValidationAttackSetting, List<SourcePayload>> mapped = new EnumMap<>(UrlValidationAttackSetting.class);
            for (SourceWordlist wordlist : wordlists) {
                mapped.put(wordlist.setting(), List.copyOf(wordlist.payloads()));
            }
            return Map.copyOf(mapped);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load URL validation source payloads", e);
        }
    }

    private static Map<String, Map<String, List<String>>> loadRenderedPayloads() {
        InputStream inputStream = UrlValidationPayloadGenerator.class.getResourceAsStream(RENDERED_RESOURCE);
        if (inputStream == null) {
            throw new IllegalStateException("Missing URL validation rendered payload resource: " + RENDERED_RESOURCE);
        }

        try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            Map<String, Map<String, List<String>>> payloads = new Gson().fromJson(reader, RENDERED_RESOURCE_TYPE);
            return Map.copyOf(payloads);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load URL validation rendered payloads", e);
        }
    }

    private record SourceWordlist(
        UrlValidationAttackSetting setting,
        String name,
        List<SourcePayload> payloads
    ) {
    }

    private record SourcePayload(
        String id,
        String payload,
        String description,
        String prefix,
        String suffix,
        Integer port,
        List<String> tags
    ) {
        boolean supports(UrlValidationContext family) {
            return tags != null && tags.contains(tagFor(family));
        }

        private String tagFor(UrlValidationContext family) {
            return switch (family) {
                case ABSOLUTE_URL -> "URL";
                case HOSTNAME -> "HOST";
                case CORS_ORIGIN -> "CORS";
            };
        }
    }
}
