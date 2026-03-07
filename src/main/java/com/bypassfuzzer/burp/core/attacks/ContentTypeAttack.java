package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.RequestBodyFormat;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Content-Type attack strategy.
 * Tests different content type encodings to find bypass vulnerabilities.
 */
public class ContentTypeAttack implements AttackStrategy {

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                        Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                        RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        try {
            api.logging().logToOutput("Starting Content-Type Attack");
        } catch (Exception e) {
            return;
        }

        int count = 0;
        Map<String, String> params = RequestParameterSupport.extractCombinedParameters(baseRequest);

        if (params.isEmpty()) {
            logError(api, "Content-Type Attack: Skipped - No parameters found to convert");
            return;
        }

        HttpRequest requestToModify = baseRequest;
        if (!RequestParameterSupport.supportsBody(baseRequest.method())) {
            try {
                api.logging().logToOutput(
                    "Content-Type Attack: Converting " + baseRequest.method() + " to POST to test content-type variations"
                );
            } catch (Exception e) {
                // Ignore
            }
            requestToModify = RequestParameterSupport.prepareForBodyFormat(baseRequest, "POST");
        }

        String currentContentType = requestToModify.headerValue("Content-Type");
        if (currentContentType == null) {
            currentContentType = "unknown";
        }

        try {
            api.logging().logToOutput(
                "Content-Type Attack: Found " + params.size() + " parameters, current type: " + currentContentType
            );
        } catch (Exception e) {
            // Ignore
        }

        count = maybeExecute(api, "application/x-www-form-urlencoded", "Content-Type: URL-encoded",
            requestToModify, params, RequestBodyFormat.URL_ENCODED, count, resultCallback, shouldContinue, rateLimiter, attackExecutor);
        if (count < 0) {
            return;
        }

        count = maybeExecute(api, "application/json", "Content-Type: JSON",
            requestToModify, params, RequestBodyFormat.JSON, count, resultCallback, shouldContinue, rateLimiter, attackExecutor);
        if (count < 0) {
            return;
        }

        count = maybeExecute(api, "application/xml", "Content-Type: XML",
            requestToModify, params, RequestBodyFormat.XML, count, resultCallback, shouldContinue, rateLimiter, attackExecutor,
            "text/xml");
        if (count < 0) {
            return;
        }

        count = maybeExecute(api, "multipart/form-data", "Content-Type: multipart/form-data",
            requestToModify, params, RequestBodyFormat.MULTIPART, count, resultCallback, shouldContinue, rateLimiter, attackExecutor);
        if (count < 0) {
            return;
        }

        try {
            api.logging().logToOutput("Content-Type Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    private int maybeExecute(MontoyaApi api, String skipIfContains, String payload,
                             HttpRequest requestToModify, Map<String, String> params, RequestBodyFormat format, int count,
                             Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                             RateLimiter rateLimiter, AttackExecutor attackExecutor, String... additionalSkips) {

        String currentContentType = requestToModify.headerValue("Content-Type");
        currentContentType = currentContentType == null ? "" : currentContentType;
        if (currentContentType.contains(skipIfContains)) {
            return count;
        }
        for (String additionalSkip : additionalSkips) {
            if (currentContentType.contains(additionalSkip)) {
                return count;
            }
        }

        if (!shouldContinue.getAsBoolean()) {
            logStop(api, count);
            return -1;
        }

        try {
            HttpRequest request = RequestParameterSupport.applyBodyFormat(requestToModify, params, format);
            if (!attackExecutor.execute(getAttackType(), payload, request, resultCallback, shouldContinue, rateLimiter)) {
                return -1;
            }
            return count + 1;
        } catch (Exception e) {
            logError(api, "Error converting payload '" + payload + "': " + e.getMessage());
            return count;
        }
    }

    private void logStop(MontoyaApi api, int count) {
        try {
            api.logging().logToOutput("Content-Type Attack stopped by user (" + count + " completed)");
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
        return "ContentType";
    }
}
