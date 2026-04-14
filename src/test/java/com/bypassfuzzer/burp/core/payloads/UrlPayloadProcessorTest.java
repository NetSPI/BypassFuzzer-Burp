package com.bypassfuzzer.burp.core.payloads;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

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
    void expandCaseVariants_doubleEncodedTripletHandled() {
        // The trailing '2e' of %252e is the hex payload of a double-encoded dot.
        // Expander must toggle its 'e' to cover decoder-case bugs on the 2nd level
        // (e.g. React %252F vs %252f).
        List<String> variants = UrlPayloadProcessor.expandCaseVariants("%252e");
        assertTrue(variants.contains("%252e"));
        assertTrue(variants.contains("%252E"));
        assertEquals(2, variants.size());
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
    void parseClassifiedPayload_untaggedGetsDefaultThreeClasses() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("../");
        assertEquals("../", c.payload);
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.PREFIX));
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SUFFIX));
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SANDWICH));
        assertFalse(c.classes.contains(UrlPayloadProcessor.InjectionClass.BETWEEN));
    }

    @Test
    void parseClassifiedPayload_suffixOnlyTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[s]?admin");
        assertEquals("?admin", c.payload);
        assertEquals(1, c.classes.size());
        assertTrue(c.classes.contains(UrlPayloadProcessor.InjectionClass.SUFFIX));
    }

    @Test
    void parseClassifiedPayload_betweenTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[b]..;");
        assertEquals("..;", c.payload);
        assertEquals(Set.of(UrlPayloadProcessor.InjectionClass.BETWEEN), c.classes);
    }

    @Test
    void parseClassifiedPayload_allTagExpandsToFourClasses() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[a]..");
        assertEquals(4, c.classes.size());
    }

    @Test
    void parseClassifiedPayload_multiCharTagParsed() {
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[pb]..");
        assertEquals(Set.of(
                UrlPayloadProcessor.InjectionClass.PREFIX,
                UrlPayloadProcessor.InjectionClass.BETWEEN), c.classes);
    }

    @Test
    void parseClassifiedPayload_bracketInPayloadNotInterpretedAsTag() {
        // A real payload can't start with '[xxx]' where xxx are all pswba chars,
        // but a payload like [xyz]... has invalid flag chars so the whole thing
        // should be treated as the raw payload (no match).
        UrlPayloadProcessor.Classified c = UrlPayloadProcessor.parseClassifiedPayload("[xyz]foo");
        assertEquals("[xyz]foo", c.payload);
        assertEquals(UrlPayloadProcessor.InjectionClass.PREFIX,
                c.classes.iterator().next()); // has default classes
    }

    @Test
    void generator_betweenInjectionInsertsNewSegment() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = processor.generateUrlPayloads(List.of("[b]..;"));
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/..;/api/v1/users")),
                "BETWEEN should produce ..; before first segment; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.contains("/api/..;/v1/users")),
                "BETWEEN should produce ..; between api and v1; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/api/v1/users/..;")),
                "BETWEEN should produce ..; after last segment; got " + out);
    }

    @Test
    void generator_suffixOnlyPayloadDoesNotAppearAsPrefix() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = processor.generateUrlPayloads(List.of("[s]?evil"));
        assertFalse(out.stream().anyMatch(u -> u.contains("/?evilapi")),
                "[s] payload should not be prefix-injected; got " + out);
        assertTrue(out.stream().anyMatch(u -> u.contains("users?evil")),
                "[s] payload should still be suffix-appended; got " + out);
    }

    @Test
    void embeddedPayloadFileLoads() {
        List<String> payloads = PayloadLoader.loadPayloads("url_payloads.txt");
        assertFalse(payloads.isEmpty(), "url_payloads.txt must load");
        assertTrue(payloads.size() > 300, "expected > 300 payloads in file, got " + payloads.size());
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
    void expandSegmentCase_fullCartesianUnderCap() {
        List<String> variants = UrlPayloadProcessor.expandSegmentCase("api");
        assertEquals(8, variants.size());
        assertTrue(variants.contains("api"));
        assertTrue(variants.contains("API"));
        assertTrue(variants.contains("Api"));
        assertTrue(variants.contains("aPi"));
        assertTrue(variants.contains("apI"));
    }

    @Test
    void expandSegmentCase_aboveCapFallsBackToAllLowerAndAllUpper() {
        List<String> variants = UrlPayloadProcessor.expandSegmentCase("dashboard");
        assertEquals(2, variants.size());
        assertTrue(variants.contains("dashboard"));
        assertTrue(variants.contains("DASHBOARD"));
    }

    @Test
    void expandSegmentCase_digitsAndSymbolsUntouched() {
        assertEquals(List.of("123"), UrlPayloadProcessor.expandSegmentCase("123"));
        List<String> v1 = UrlPayloadProcessor.expandSegmentCase("v1");
        assertEquals(2, v1.size());
        assertTrue(v1.contains("v1"));
        assertTrue(v1.contains("V1"));
    }

    @Test
    void generator_outputIsDeterministicAcrossRuns() throws Exception {
        UrlPayloadProcessor p1 = new UrlPayloadProcessor("https://example.com/api/v1/users");
        UrlPayloadProcessor p2 = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out1 = p1.generateUrlPayloads(List.of("../", "%2e%2e%2f"));
        List<String> out2 = p2.generateUrlPayloads(List.of("../", "%2e%2e%2f"));
        assertEquals(out1, out2, "two runs must produce identical URLs (was flaky under old random-case)");
    }

    @Test
    void generator_wholePathAllUpperAppears() throws Exception {
        UrlPayloadProcessor p = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> out = p.generateUrlPayloads(List.of());
        assertTrue(out.stream().anyMatch(u -> u.endsWith("/API/V1/USERS")),
                "whole-path all-upper URL should appear; got " + out);
    }

    @Test
    void crossEncodingChains_areHeterogeneous() {
        List<String> chains = UrlPayloadProcessor.generateCrossEncodingChains();
        assertEquals(20, chains.size(), "expected 5 primitives * 4 non-self = 20 chains");
        for (String chain : chains) {
            assertFalse(chain.equals("../../"), "chain should never be homogeneous self-pair");
            assertFalse(chain.equals("..%2f..%2f"), "chain should never be homogeneous self-pair");
        }
        assertTrue(chains.contains("../..%2f"));
        assertTrue(chains.contains("..%2f../"));
        assertTrue(chains.contains("..;/%2e%2e%2f"));
    }

    @Test
    void crossEncodingChains_appearInGeneratedUrls() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/api/v1/users");
        List<String> urls = processor.generateUrlPayloads(List.of());
        assertTrue(urls.stream().anyMatch(u -> u.contains("../..%2f")),
                "cross-encoded chain ../..%2f should appear somewhere in URLs");
        assertTrue(urls.stream().anyMatch(u -> u.contains("%2e%2e%2f..;/")
                        || u.contains("..;/%2e%2e%2f")),
                "at least one ..;/ <-> %2e%2e%2f cross-chain should appear");
    }

    @Test
    void rootUrlWithBetweenTagProducesPayloads() throws Exception {
        UrlPayloadProcessor processor = new UrlPayloadProcessor("https://example.com/");
        List<String> generated = processor.generateUrlPayloads(List.of("[b]..;", "[b]%2e%2e"));
        assertFalse(generated.isEmpty(), "root URL with [b] payloads should produce URLs");
        assertTrue(generated.stream().anyMatch(u -> u.contains("..;")),
                "expected ..; to appear in some root-targeted URL; got " + generated);
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
            // Strip any classification tag (e.g. [s]?) to the raw payload content;
            // that's what actually reaches the wire.
            String content = UrlPayloadProcessor.parseClassifiedPayload(p).payload;
            boolean verbatim = generated.stream().anyMatch(u -> u.contains(content));
            String mangled = content.replace("%", "%25");
            boolean mangledPresent = !content.equals(mangled)
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
