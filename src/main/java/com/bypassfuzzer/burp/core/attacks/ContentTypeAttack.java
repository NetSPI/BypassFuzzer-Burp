package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.RequestBodyFormat;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.List;
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

        if (!AttackExecutionSupport.logStart(api, "Starting Content-Type Attack")) {
            return;
        }

        int count = 0;
        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(baseRequest);

        if (params.isEmpty()) {
            AttackExecutionSupport.logError(api, "Content-Type Attack: Skipped - No parameters found to convert");
            return;
        }

        HttpRequest requestToModify = baseRequest;
        if (!RequestParameterSupport.supportsBody(baseRequest.method())) {
            AttackExecutionSupport.logOutput(
                api,
                "Content-Type Attack: Converting " + baseRequest.method() + " to POST to test content-type variations"
            );
            requestToModify = RequestParameterSupport.prepareForBodyFormat(baseRequest, "POST");
        }

        String currentContentType = requestToModify.headerValue("Content-Type");
        if (currentContentType == null) {
            currentContentType = "unknown";
        }

        AttackExecutionSupport.logOutput(
            api,
            "Content-Type Attack: Found " + params.size() + " parameters, current type: " + currentContentType
        );

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

        AttackExecutionSupport.logOutput(api, "Content-Type Attack completed: " + count + " results sent");
    }

    private int maybeExecute(MontoyaApi api, String skipIfContains, String payload,
                             HttpRequest requestToModify, List<LocatedParameter> params, RequestBodyFormat format, int count,
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

        if (AttackExecutionSupport.stopIfRequested(
            api,
            shouldContinue,
            "Content-Type Attack stopped by user (" + count + " completed)"
        )) {
            return -1;
        }

        try {
            HttpRequest request = RequestParameterSupport.applyBodyFormat(requestToModify, params, format);
            if (!attackExecutor.execute(getAttackType(), payload, request, resultCallback, shouldContinue, rateLimiter)) {
                return -1;
            }
            return count + 1;
        } catch (Exception e) {
            if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Error converting payload '" + payload + "': ", e)) {
                return -1;
            }
            return count;
        }
    }

    @Override
    public String getAttackType() {
        return "ContentType";
    }
}
