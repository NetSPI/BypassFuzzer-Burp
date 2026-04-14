package com.bypassfuzzer.burp.core.payloads;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlPayloadProcessorTest {

    @Test
    void expandCaseVariants_noHexLettersReturnsOriginalOnly() {
        assertEquals(List.of("../"), UrlPayloadProcessor.expandCaseVariants("../"));
        assertEquals(List.of("%20%23"), UrlPayloadProcessor.expandCaseVariants("%20%23"));
    }

    @Test
    void expandCaseVariants_singleLetterProducesBothCases() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%2e");
        assertTrue(variants.contains("%2e"));
        assertTrue(variants.contains("%2E"));
        assertEquals(2, variants.size());
    }

    @Test
    void expandCaseVariants_percentUFiveArgFormNotTouched() {
        // %u002e is IIS-style Unicode escape (not a real percent-encoding). The '%u'
        // prefix is not a valid %XX triplet, so the expander leaves it verbatim.
        // To exercise both cases we rely on the hand-written %U002E variant in the file.
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%u002e");
        assertEquals(List.of("%u002e"), variants);
    }

    @Test
    void expandCaseVariants_multiLetterCartesian() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%2e%2f");
        assertTrue(variants.contains("%2e%2f"));
        assertTrue(variants.contains("%2E%2f"));
        assertTrue(variants.contains("%2e%2F"));
        assertTrue(variants.contains("%2E%2F"));
        assertEquals(4, variants.size());
    }

    @Test
    void expandCaseVariants_aboveCapFallsBackToJustAllLowerAndAllUpper() {
        // %ef%bc%8f has 5 hex letters (e,f,b,c,f) > LETTER_CAP=4.
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%ef%bc%8f");
        assertTrue(variants.contains("%ef%bc%8f"));
        assertTrue(variants.contains("%EF%BC%8F"));
        assertTrue(variants.size() <= 3);
    }

    @Test
    void expandCaseVariants_preservesNonLetterBytes() {
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("/%2e%2e/admin");
        for (String v : variants) {
            assertTrue(v.startsWith("/") && v.endsWith("/admin"),
                    "non-hex bytes should be untouched: " + v);
        }
    }

    @Test
    void embeddedPayloadFileLoads() {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        assertFalse(payloads.isEmpty(), "url_payloads.txt must load");
        assertTrue(payloads.size() > 500, "expected > 500 payloads after cleanup, got " + payloads.size());
        for (String p : payloads) {
            assertFalse(p.trim().startsWith("#"), "comment leaked into payload list: " + p);
            assertFalse(p.isBlank(), "blank payload leaked into list");
        }
    }

    @Test
    void processorGeneratesUrlsForEveryPayloadWithoutThrowing() throws Exception {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");

        List<String> generated = processor.generateUrlPayloads(payloads);

        assertFalse(generated.isEmpty(), "processor produced zero URLs");
        for (String url : generated) {
            assertTrue(url.startsWith("https://example.com/"),
                    "generated URL escaped origin: " + url);
        }
    }

    @Test
    void rootOnlyUrlProducesSuffixPayloadsOnly() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/");
        List<String> generated = processor.generateUrlPayloads(List.of("../", "..%2f"));
        assertTrue(generated.isEmpty() || generated.stream().allMatch(u -> u.startsWith("https://example.com/")),
                "root-only URL should not produce foreign origins");
    }

    @Test
    void reportPayloadSurvivalAndManglingRate() throws Exception {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> generated = processor.generateUrlPayloads(payloads);

        int survived = 0;
        int onlyMangled = 0;
        List<String> vanished = new java.util.ArrayList<>();

        for (String p : payloads) {
            boolean verbatim = generated.stream().anyMatch(u -> u.contains(p));
            String mangled = p.replace("%", "%25");
            boolean mangledPresent = !p.equals(mangled)
                    && generated.stream().anyMatch(u -> u.contains(mangled));

            if (verbatim) {
                survived++;
            } else if (mangledPresent) {
                onlyMangled++;
            } else {
                vanished.add(p);
            }
        }

        System.out.println("=== UrlPayloadProcessor survival report ===");
        System.out.println("Input payloads:     " + payloads.size());
        System.out.println("Output URLs:        " + generated.size());
        System.out.println("Verbatim survivors: " + survived);
        System.out.println("Only mangled (%->%25): " + onlyMangled);
        System.out.println("Vanished entirely:  " + vanished.size());
        if (!vanished.isEmpty()) {
            int show = Math.min(vanished.size(), 40);
            for (int i = 0; i < show; i++) {
                System.out.println("  VANISHED: " + vanished.get(i));
            }
            if (vanished.size() > show) {
                System.out.println("  ... and " + (vanished.size() - show) + " more");
            }
        }

        assertTrue(survived + onlyMangled >= payloads.size() * 9 / 10,
                "less than 90% of payloads survived processor (verbatim+mangled): "
                        + (survived + onlyMangled) + "/" + payloads.size());
    }
}
