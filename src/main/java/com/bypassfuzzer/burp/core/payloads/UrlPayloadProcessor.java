package com.bypassfuzzer.burp.core.payloads;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generates URL/path manipulation payloads by injecting patterns into each path segment.
 *
 * For URL: https://example.com/test1/test2/test3
 * And payload: "../"
 * Generates:
 * - ../test1/test2/test3
 * - test1../test2/test3
 * - ../test1../test2/test3
 * - test1/../test2/test3
 * - etc.
 */
public class UrlPayloadProcessor {

    private final String targetUrl;
    private final URI uri;
    private final List<String> pathSegments;

    public UrlPayloadProcessor(String targetUrl) throws URISyntaxException {
        this.targetUrl = targetUrl;
        this.uri = new URI(targetUrl);
        this.pathSegments = parsePathSegments(uri.getPath());
    }

    /**
     * Generate all URL payload permutations.
     *
     * @param urlPayloads List of URL encoding/manipulation patterns
     * @return List of complete URLs with payloads applied
     */
    public List<String> generateUrlPayloads(List<String> urlPayloads) {
        Set<String> allPaths = new LinkedHashSet<>();

        // Expand each payload into its case variants (e.g. %2e -> {%2e, %2E}) so we
        // catch decoder-case bugs without hand-maintaining every variant in the file.
        List<String> expandedPayloads = expandAllCaseVariants(urlPayloads);

        // Generate path permutations for each payload and path segment
        for (int i = 0; i < pathSegments.size(); i++) {
            for (String payload : expandedPayloads) {
                String segment = pathSegments.get(i);

                // Pattern 1: payload + segment (e.g., ../test1)
                List<String> newSegments = new ArrayList<>(pathSegments);
                newSegments.set(i, payload + segment);
                allPaths.add(String.join("/", newSegments));

                // Pattern 2: segment + payload (e.g., test1../)
                newSegments = new ArrayList<>(pathSegments);
                newSegments.set(i, segment + payload);
                allPaths.add(String.join("/", newSegments));

                // Pattern 3: payload + segment + payload (e.g., ../test1../)
                newSegments = new ArrayList<>(pathSegments);
                newSegments.set(i, payload + segment + payload);
                allPaths.add(String.join("/", newSegments));
            }

            // Random capitalization (5 variations)
            for (int r = 0; r < 5; r++) {
                List<String> newSegments = new ArrayList<>(pathSegments);
                newSegments.set(i, randomCapitalize(pathSegments.get(i)));
                allPaths.add(String.join("/", newSegments));
            }
        }

        // Add query/extension suffix payloads to the last segment
        List<String> suffixPayloads = new ArrayList<>();
        if (!pathSegments.isEmpty()) {
            suffixPayloads = generateSuffixPayloads();
            for (String suffix : suffixPayloads) {
                List<String> newSegments = new ArrayList<>(pathSegments);
                newSegments.set(newSegments.size() - 1, pathSegments.get(pathSegments.size() - 1) + suffix);
                allPaths.add(String.join("/", newSegments));
            }
        }

        // Convert paths back to full URLs
        return convertPathsToUrls(new ArrayList<>(allPaths), suffixPayloads);
    }

    // Captures the 2-hex-digit payload of a single- or double-level percent-encoding.
    // %XX matches the inner hex; %25XX matches the inner hex of a double-encoded form
    // (important for decoder-case bugs like React's %252F vs %252f).
    private static final Pattern PCT_TRIPLET = Pattern.compile("%(?:25)?([0-9a-fA-F]{2})");
    // 2^LETTER_CAP is the max variants emitted per payload via full Cartesian expansion.
    // Beyond the cap we fall back to just [all-lower-hex, all-upper-hex].
    private static final int LETTER_CAP = 4;

    static List<String> expandAllCaseVariants(List<String> payloads) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String p : payloads) {
            out.addAll(expandCaseVariants(p));
        }
        return new ArrayList<>(out);
    }

    /**
     * Emit case variants of every %XX triplet in the payload. Digits are left alone,
     * hex letters (a-f/A-F) are toggled independently. Input payload is always kept
     * verbatim. Bounded expansion: up to 2^LETTER_CAP full variants, otherwise just
     * the original + all-lower + all-upper.
     */
    static List<String> expandCaseVariants(String payload) {
        List<Integer> letterPositions = new ArrayList<>();
        Matcher m = PCT_TRIPLET.matcher(payload);
        while (m.find()) {
            for (int i = m.start(1); i < m.end(1); i++) {
                char c = payload.charAt(i);
                if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                    letterPositions.add(i);
                }
            }
        }
        if (letterPositions.isEmpty()) {
            return Collections.singletonList(payload);
        }

        LinkedHashSet<String> out = new LinkedHashSet<>();
        out.add(payload);
        int n = letterPositions.size();

        if (n <= LETTER_CAP) {
            for (int mask = 0; mask < (1 << n); mask++) {
                out.add(applyLetterCase(payload, letterPositions, mask));
            }
        } else {
            out.add(applyLetterCase(payload, letterPositions, 0));
            out.add(applyLetterCase(payload, letterPositions, (1 << n) - 1));
        }
        return new ArrayList<>(out);
    }

    private static String applyLetterCase(String payload, List<Integer> positions, int mask) {
        StringBuilder sb = new StringBuilder(payload);
        for (int i = 0; i < positions.size(); i++) {
            int pos = positions.get(i);
            char c = payload.charAt(pos);
            boolean upper = ((mask >> i) & 1) == 1;
            sb.setCharAt(pos, upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private List<String> parsePathSegments(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) {
            return new ArrayList<>();
        }

        String[] parts = path.split("/");
        List<String> segments = new ArrayList<>();
        for (String part : parts) {
            if (!part.isEmpty()) {
                segments.add(part);
            }
        }
        return segments;
    }

    private String randomCapitalize(String str) {
        Random random = new Random();
        StringBuilder result = new StringBuilder();
        for (char c : str.toCharArray()) {
            result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return result.toString();
    }

    private List<String> generateSuffixPayloads() {
        List<String> baseSuffixes = Arrays.asList(
            "?debug=true",
            "?admin=true",
            "?user=admin",
            "?detail=true",
            ".html",
            "?.html",
            "%3f.html",
            ".json",
            "?.json",
            "%3f.json",
            ".php",
            "?.php",
            "%3f.php",
            "?wsdl",
            "/application.wadl?detail=true"
        );

        Set<String> allSuffixes = new LinkedHashSet<>(baseSuffixes);

        // Add random capitalization variations
        for (String suffix : baseSuffixes) {
            for (int i = 0; i < 3; i++) {
                allSuffixes.add(randomCapitalize(suffix));
            }
        }

        return new ArrayList<>(allSuffixes);
    }

    private List<String> convertPathsToUrls(List<String> paths, List<String> suffixPayloads) {
        // Build URLs via raw string assembly. Java's URI(scheme,authority,path,query,fragment)
        // constructor re-escapes '%' to '%25', which destroys every %-encoded payload
        // (%2e -> %252e, case variants collapse, etc.). We need bytes on the wire to match
        // what's in url_payloads.txt exactly.
        List<String> urls = new ArrayList<>();
        String originalQuery = uri.getQuery();
        String base = uri.getScheme() + "://" + uri.getAuthority();

        for (String path : paths) {
            String lastSegment = path.substring(path.lastIndexOf('/') + 1);
            boolean hasQuerySuffix = suffixPayloads.stream().anyMatch(lastSegment::contains);

            if (hasQuerySuffix) {
                urls.add(base + "/" + path);

                if (originalQuery != null && !originalQuery.isEmpty() &&
                    (lastSegment.contains("?") || lastSegment.toLowerCase().contains("%3f"))) {
                    urls.add(base + "/" + path + "&" + originalQuery);
                }
            } else if (originalQuery != null && !originalQuery.isEmpty()) {
                urls.add(base + "/" + path + "?" + originalQuery);
            } else {
                urls.add(base + "/" + path);
            }
        }

        return urls;
    }
}
