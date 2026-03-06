package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Debug parameter injection attack.
 * Appends debug/admin query parameters to bypass access controls.
 *
 * Attack order:
 * 1. Fuzz existing URL params (preserve name case, try different values)
 * 2. Add new URL params (standard payloads)
 */
public class ParamAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Param";
    private static final String EXISTING_PARAM_TYPE = "Param (Existing)";

    // Values to try when fuzzing existing params
    private static final String[] FUZZ_VALUES = {
        "true", "1", "yes", "on", "admin", "root", "false", "0", "no", "off"
    };

    public ParamAttack() {
        // Default constructor
    }

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning, RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        List<String> paramPayloads = buildParamPayloads();

        // Extract just the path+query from the full URL
        String basePath = extractPathAndQuery(targetUrl);

        // Phase 1: Fuzz existing URL query parameters first
        fuzzExistingUrlParams(originalRequest, basePath, resultCallback, isRunning, rateLimiter, attackExecutor);

        // Phase 2: Add new URL query string parameters
        executeUrlParamAttacks(api, originalRequest, basePath, paramPayloads, resultCallback, isRunning, rateLimiter, attackExecutor);
    }

    /**
     * Fuzz existing URL query parameters by trying different values while preserving param name case.
     */
    private void fuzzExistingUrlParams(HttpRequest originalRequest, String basePath,
                                       Consumer<AttackResult> resultCallback, BooleanSupplier isRunning,
                                       RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        // Parse existing query parameters
        Map<String, String> existingParams = parseQueryParams(basePath);
        if (existingParams.isEmpty()) {
            return;
        }

        // Get path without query string
        String pathOnly = basePath.contains("?") ? basePath.substring(0, basePath.indexOf("?")) : basePath;

        for (Map.Entry<String, String> param : existingParams.entrySet()) {
            String paramName = param.getKey();

            // Try each fuzz value for this parameter
            for (String fuzzValue : FUZZ_VALUES) {
                if (!isRunning.getAsBoolean()) {
                    return;
                }

                try {
                    // Build new query string with modified value for this param
                    StringBuilder newQuery = new StringBuilder();
                    for (Map.Entry<String, String> p : existingParams.entrySet()) {
                        if (newQuery.length() > 0) {
                            newQuery.append("&");
                        }
                        if (p.getKey().equals(paramName)) {
                            // Use fuzz value for this param
                            newQuery.append(paramName).append("=").append(fuzzValue);
                        } else {
                            // Keep original value
                            newQuery.append(p.getKey()).append("=").append(p.getValue());
                        }
                    }

                    String modifiedPath = pathOnly + "?" + newQuery;

                    HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);
                    if (!attackExecutor.execute(EXISTING_PARAM_TYPE, paramName + "=" + fuzzValue, modifiedRequest, resultCallback, isRunning, rateLimiter)) {
                        return;
                    }
                } catch (Exception e) {
                    // caller logs with API when available
                }
            }
        }
    }

    /**
     * Execute standard URL query parameter attacks (adding new params).
     */
    private void executeUrlParamAttacks(MontoyaApi api, HttpRequest originalRequest, String basePath,
                                        List<String> paramPayloads, Consumer<AttackResult> resultCallback,
                                        BooleanSupplier isRunning, RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        for (String param : paramPayloads) {
            if (!isRunning.getAsBoolean()) {
                break;
            }

            try {
                String modifiedPath = appendParameter(basePath, param);

                HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);
                if (!attackExecutor.execute(ATTACK_TYPE, param, modifiedRequest, resultCallback, isRunning, rateLimiter)) {
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("Error in param attack with payload '" + param + "': " + e.getMessage());
            }
        }
    }

    /**
     * Parse query parameters from a URL path.
     * Returns a LinkedHashMap to preserve order.
     */
    private Map<String, String> parseQueryParams(String pathWithQuery) {
        Map<String, String> params = new LinkedHashMap<>();

        int queryStart = pathWithQuery.indexOf("?");
        if (queryStart == -1 || queryStart == pathWithQuery.length() - 1) {
            return params;
        }

        String queryString = pathWithQuery.substring(queryStart + 1);
        String[] pairs = queryString.split("&");

        for (String pair : pairs) {
            int eqIdx = pair.indexOf("=");
            if (eqIdx > 0) {
                String name = pair.substring(0, eqIdx);
                String value = eqIdx < pair.length() - 1 ? pair.substring(eqIdx + 1) : "";
                try {
                    // Decode URL-encoded values but preserve the name as-is
                    params.put(name, URLDecoder.decode(value, StandardCharsets.UTF_8.name()));
                } catch (Exception e) {
                    params.put(name, value);
                }
            } else if (!pair.isEmpty()) {
                // Param with no value
                params.put(pair, "");
            }
        }

        return params;
    }

    /**
     * Build list of debug parameter payloads from resource file.
     */
    private List<String> buildParamPayloads() {
        List<String> basePayloads = loadPayloadsFromResource();

        // Add case variations
        List<String> allPayloads = new ArrayList<>(basePayloads);
        for (String payload : basePayloads) {
            // First add systematic case variations (more likely to hit common patterns)
            allPayloads.add(capitalizeParamName(payload));  // admin=true -> Admin=true
            allPayloads.add(upperCaseParamName(payload));   // admin=true -> ADMIN=true

            // Then generate 3 random case variations per payload
            for (int i = 0; i < 3; i++) {
                allPayloads.add(randomizeCase(payload));
            }
        }

        return allPayloads;
    }

    /**
     * Capitalize first letter of parameter name (camelCase style).
     * admin=true -> Admin=true
     */
    private String capitalizeParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }
        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);

        if (name.isEmpty()) {
            return payload;
        }

        return Character.toUpperCase(name.charAt(0)) + name.substring(1).toLowerCase() + value;
    }

    /**
     * Convert parameter name to all uppercase.
     * admin=true -> ADMIN=true
     */
    private String upperCaseParamName(String payload) {
        int eqIdx = payload.indexOf('=');
        if (eqIdx <= 0) {
            return payload;
        }
        String name = payload.substring(0, eqIdx);
        String value = payload.substring(eqIdx);

        return name.toUpperCase() + value;
    }

    /**
     * Load parameter payloads from resource file.
     */
    private List<String> loadPayloadsFromResource() {
        List<String> payloads = new ArrayList<>();

        try (InputStream is = getClass().getResourceAsStream("/payloads/param_payloads.txt");
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    payloads.add(line);
                }
            }
        } catch (Exception e) {
            // Fallback to default payloads if resource file can't be loaded
            payloads.add("debug=true");
            payloads.add("debug=1");
            payloads.add("admin=true");
            payloads.add("admin=1");
        }

        return payloads;
    }

    /**
     * Randomize capitalization of characters in a string.
     * Creates variations like: admin=true -> Admin=true, aDmin=true, etc.
     */
    private String randomizeCase(String input) {
        Random random = new Random();
        StringBuilder result = new StringBuilder();

        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                // Randomly choose upper or lower case
                if (random.nextBoolean()) {
                    result.append(Character.toUpperCase(c));
                } else {
                    result.append(Character.toLowerCase(c));
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * Extract path and query from a full URL.
     * Converts "https://example.com/path?query" to "/path?query"
     */
    private String extractPathAndQuery(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
            // If no path found, return root
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    /**
     * Append parameter to URL, handling existing query strings.
     */
    private String appendParameter(String url, String param) {
        // Check if URL already has query string
        if (url.contains("?")) {
            return url + "&" + param;
        } else {
            return url + "?" + param;
        }
    }
}
