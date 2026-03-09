package com.bypassfuzzer.burp.core.urlvalidation;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlValidationPayloadGeneratorTest {

    @Test
    void intrudersEncodingPercentEncodesSelectedCharactersAcrossFamilies() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            "http",
            Set.of(UrlValidationContext.ABSOLUTE_URL, UrlValidationContext.HOSTNAME, UrlValidationContext.CORS_ORIGIN),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            UrlValidationEncoding.INTRUDERS,
            0,
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(409, payloads.size());
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.encoding() == UrlValidationEncoding.INTRUDERS
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.CORS_ORIGIN
                && payload.encoding() == UrlValidationEncoding.INTRUDERS
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().contains("127.0.0.1")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("https://%5B::%5D/")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("%0D%0A//127.0.0.1")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("https://%400/")
        ));
        assertFalse(payloads.stream().anyMatch(payload ->
            payload.family() == UrlValidationContext.ABSOLUTE_URL
                && payload.value().equals("https://%0D%0A//127.0.0.1")
        ));
    }

    @Test
    void selectedFamiliesLimitPayloadGeneration() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            "http",
            Set.of(UrlValidationContext.CORS_ORIGIN),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK
            ),
            UrlValidationEncoding.UNICODE_ESCAPE,
            0,
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(28, payloads.size());
        assertTrue(payloads.stream().allMatch(payload -> payload.family() == UrlValidationContext.CORS_ORIGIN));
        assertEquals(
            payloads.size(),
            payloads.stream().filter(payload -> payload.encoding() == UrlValidationEncoding.UNICODE_ESCAPE).count()
        );
        assertTrue(payloads.stream().anyMatch(payload -> payload.value().equals("null")));
    }

    @Test
    void optionalAttackSettingsAppendToRenderedDefaultPayloads() {
        UrlValidationPayloadGenerator generator = new UrlValidationPayloadGenerator();
        UrlValidationCandidate candidate = new UrlValidationCandidate(
            "{INJECT}",
            "{INJECT}",
            "marker",
            (request, newValue) -> request
        );
        UrlValidationOptions options = new UrlValidationOptions(
            "{INJECT}",
            "trusted.example",
            "127.0.0.1",
            "https",
            Set.of(UrlValidationContext.ABSOLUTE_URL),
            Set.of(
                UrlValidationAttackSetting.DOMAIN_ALLOW_LIST_BYPASS,
                UrlValidationAttackSetting.FAKE_RELATIVE_URLS,
                UrlValidationAttackSetting.LOOPBACK,
                UrlValidationAttackSetting.CLOUD_METADATA_ENDPOINTS
            ),
            UrlValidationEncoding.INTRUDERS,
            0,
            Set.of()
        );

        List<UrlValidationPayload> payloads = generator.generate(candidate, options);

        assertEquals(251, payloads.size());
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.value().equals("http://169.254.169.254/latest/meta-data/")
        ));
        assertTrue(payloads.stream().anyMatch(payload ->
            payload.value().equals("https://%5B::%5D/")
        ));
    }
}
