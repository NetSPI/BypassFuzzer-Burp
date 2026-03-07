package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;
import com.bypassfuzzer.burp.http.RequestParameterSupport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Verb/Method attack strategy.
 * Tests different HTTP methods and method override headers.
 */
public class VerbAttack implements AttackStrategy {
    private static final List<String> HTTP_METHODS = Arrays.asList(
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
    );
    private static final List<String> OVERRIDE_HEADERS = Arrays.asList(
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override"
    );
    private static final List<String> BODY_METHODS = Arrays.asList("POST", "PUT", "PATCH");

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                        Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                        RateLimiter rateLimiter, AttackExecutor attackExecutor) {
        try {
            api.logging().logToOutput("Starting Verb Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;

        for (String method : HTTP_METHODS) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                HttpRequest modifiedRequest = createMethodRequest(baseRequest, method);
                if (!attackExecutor.execute(getAttackType(), "Method: " + method, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                    return;
                }
                count++;
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                logError(api, "Verb attack error with method " + method + ": " + e.getMessage());
            }
        }

        String originalMethod = baseRequest.method();
        for (String methodVariation : generateMethodCaseVariations(originalMethod)) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                HttpRequest modifiedRequest = baseRequest.withMethod(methodVariation);
                if (!attackExecutor.execute(getAttackType(), "Method: " + methodVariation + " (case)", modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                    return;
                }
                count++;
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                logError(api, "Verb attack error with method case variation " + methodVariation + ": " + e.getMessage());
            }
        }

        for (String xMethod : Arrays.asList("X" + originalMethod, originalMethod + "X")) {
            if (!shouldContinue.getAsBoolean()) {
                logStop(api, count);
                return;
            }

            try {
                HttpRequest modifiedRequest = baseRequest.withMethod(xMethod);
                if (!attackExecutor.execute(getAttackType(), "Method: " + xMethod, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                    return;
                }
                count++;
            } catch (NullPointerException e) {
                return;
            } catch (Exception e) {
                logError(api, "Verb attack error with X-variation " + xMethod + ": " + e.getMessage());
            }
        }

        for (String header : OVERRIDE_HEADERS) {
            for (String method : HTTP_METHODS) {
                if (!shouldContinue.getAsBoolean()) {
                    logStop(api, count);
                    return;
                }

                try {
                    HttpRequest modifiedRequest = RequestHeaderUtils.upsertHeader(baseRequest, header, method);
                    if (!attackExecutor.execute(getAttackType(), header + ": " + method, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                        return;
                    }
                    count++;
                } catch (NullPointerException e) {
                    return;
                } catch (Exception e) {
                    logError(api, "Verb attack error with override " + header + "/" + method + ": " + e.getMessage());
                }
            }
        }

        for (String baseMethod : Arrays.asList("POST", "PUT")) {
            for (String header : OVERRIDE_HEADERS) {
                for (String overrideMethod : Arrays.asList("GET", "DELETE", "PATCH")) {
                    if (!shouldContinue.getAsBoolean()) {
                        logStop(api, count);
                        return;
                    }

                    try {
                        HttpRequest modifiedRequest = RequestHeaderUtils.upsertHeader(baseRequest.withMethod(baseMethod), header, overrideMethod);
                        String payload = baseMethod + " + " + header + ": " + overrideMethod;
                        if (!attackExecutor.execute(getAttackType(), payload, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                            return;
                        }
                        count++;
                    } catch (NullPointerException e) {
                        return;
                    } catch (Exception e) {
                        logError(api, "Verb attack error: " + e.getMessage());
                    }
                }
            }
        }

        count += testParameterVariations(api, baseRequest, resultCallback, shouldContinue, rateLimiter, attackExecutor);

        try {
            api.logging().logToOutput("Verb Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    private HttpRequest createMethodRequest(HttpRequest baseRequest, String method) {
        if (BODY_METHODS.contains(method)) {
            return baseRequest.withMethod(method);
        }

        if (BODY_METHODS.contains(baseRequest.method())
            && ("GET".equals(method) || "HEAD".equals(method) || "DELETE".equals(method))) {
            String bodyParams = RequestParameterSupport.extractUrlEncodedBody(baseRequest);
            if (bodyParams != null && !bodyParams.isEmpty()) {
                return RequestParameterSupport.moveBodyToQuery(baseRequest, method, bodyParams);
            }
        }

        return baseRequest.withMethod(method);
    }

    private int testParameterVariations(MontoyaApi api, HttpRequest baseRequest,
                                        Consumer<AttackResult> resultCallback,
                                        BooleanSupplier shouldContinue,
                                        RateLimiter rateLimiter,
                                        AttackExecutor attackExecutor) {
        int count = 0;

        for (String method : BODY_METHODS) {
            if (!shouldContinue.getAsBoolean()) {
                return count;
            }

            String queryParams = baseRequest.query();
            String bodyParams = RequestParameterSupport.extractUrlEncodedBody(baseRequest);

            if ((queryParams == null || queryParams.isEmpty()) && (bodyParams == null || bodyParams.isEmpty())) {
                continue;
            }

            if (queryParams != null && !queryParams.isEmpty()) {
                if (!shouldContinue.getAsBoolean()) {
                    return count;
                }

                try {
                    HttpRequest request = RequestParameterSupport.moveQueryToBody(baseRequest, method);
                    if (!attackExecutor.execute(getAttackType(), method + " (params query→body)", request, resultCallback, shouldContinue, rateLimiter)) {
                        return count;
                    }
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing query→body: " + e.getMessage());
                }
            }

            if (bodyParams != null && !bodyParams.isEmpty()) {
                if (!shouldContinue.getAsBoolean()) {
                    return count;
                }

                try {
                    HttpRequest request = RequestParameterSupport.moveBodyToQuery(baseRequest, method, bodyParams);
                    if (!attackExecutor.execute(getAttackType(), method + " (params body→query)", request, resultCallback, shouldContinue, rateLimiter)) {
                        return count;
                    }
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing body→query: " + e.getMessage());
                }
            }

            if ((queryParams != null && !queryParams.isEmpty()) || (bodyParams != null && !bodyParams.isEmpty())) {
                if (!shouldContinue.getAsBoolean()) {
                    return count;
                }

                try {
                    String params = queryParams != null && !queryParams.isEmpty() ? queryParams : bodyParams;
                    HttpRequest request = RequestParameterSupport.putParamsInBoth(baseRequest, method, params);
                    if (!attackExecutor.execute(getAttackType(), method + " (params in query+body)", request, resultCallback, shouldContinue, rateLimiter)) {
                        return count;
                    }
                    count++;
                } catch (Exception e) {
                    logError(api, "Error testing params in both: " + e.getMessage());
                }
            }
        }

        return count;
    }

    private List<String> generateMethodCaseVariations(String method) {
        List<String> variations = new ArrayList<>();
        if (method == null || method.isEmpty()) {
            return variations;
        }

        String lowercase = method.toLowerCase();
        String titleCase = Character.toUpperCase(method.charAt(0)) + method.substring(1).toLowerCase();

        if (!lowercase.equals(method)) {
            variations.add(lowercase);
        }
        if (!titleCase.equals(method) && !titleCase.equals(lowercase)) {
            variations.add(titleCase);
        }

        for (int i = 0; i < 3; i++) {
            String randomized = randomizeCase(method);
            if (!randomized.equals(method) && !randomized.equals(lowercase) && !randomized.equals(titleCase)) {
                variations.add(randomized);
            }
        }

        return variations;
    }

    private String randomizeCase(String input) {
        Random random = new Random();
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                result.append(random.nextBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private void logStop(MontoyaApi api, int count) {
        try {
            api.logging().logToOutput("Verb Attack stopped by user (" + count + " completed)");
        } catch (Exception e) {
            // Ignore
        }
    }

    private void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {
            // Ignore
        }
    }

    @Override
    public String getAttackType() {
        return "Verb";
    }
}
