package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.HeaderPayloadProcessor;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class HeaderAttack implements AttackStrategy {
    private final HeaderPayloadProcessor processor;
    private final List<String> headerTemplates;
    private final List<String> ipPayloads;
    private final boolean collaboratorEnabled;

    public HeaderAttack(String targetUrl, String oobPayload, boolean enableCollaborator) {
        this.collaboratorEnabled = enableCollaborator;
        this.processor = new HeaderPayloadProcessor(targetUrl, oobPayload);
        this.headerTemplates = PayloadLoader.loadPayloads("header_payload_templates.txt");
        this.ipPayloads = PayloadLoader.loadPayloads("ip_payloads.txt");
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter, AttackExecutor attackExecutor) {
        // Process header templates with dynamic Collaborator payload generation
        List<String> headerPayloads = processor.processHeaderTemplates(
            headerTemplates,
            ipPayloads,
            collaboratorEnabled ? api : null
        );

        if (!AttackExecutionSupport.logStart(api, "Starting Header Attack: " + headerPayloads.size() + " total payloads")) {
            return;
        }

        int count = 0;

        for (String payload : headerPayloads) {
            if (AttackExecutionSupport.stopIfRequested(
                api,
                shouldContinue,
                "Header Attack stopped by user (" + count + " of " + headerPayloads.size() + " completed)"
            )) {
                return;
            }

            // Log progress every 100 requests
            if (count % 100 == 0 && count > 0) {
                AttackExecutionSupport.logOutput(api, "Header Attack progress: " + count + " of " + headerPayloads.size() + " requests sent");
            }

            try {
                String[] parts = payload.split(":", 2);
                if (parts.length != 2) {
                    continue;
                }

                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                HttpRequest modifiedRequest;
                String displayPayload;

                // Check for PATH_SWAP marker
                if (headerValue.endsWith(" [PATH_SWAP]")) {
                    // Remove marker, swap path to /
                    headerValue = headerValue.replace(" [PATH_SWAP]", "");
                    modifiedRequest = RequestHeaderUtils.applyAttackHeader(baseRequest.withPath("/"), headerName, headerValue);
                    displayPayload = headerName + ": " + headerValue + " (path→/)";
                } else {
                    modifiedRequest = RequestHeaderUtils.applyAttackHeader(baseRequest, headerName, headerValue);
                    displayPayload = payload;
                }

                if (!attackExecutor.execute(getAttackType(), displayPayload, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                    return;
                }
                count++;
            } catch (Exception e) {
                if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Header attack error with payload: " + payload + " - ", e)) {
                    return;
                }
            }
        }

        AttackExecutionSupport.logOutput(api, "Header Attack completed: " + count + " results sent");
    }

    @Override
    public String getAttackType() {
        return "Header";
    }
}
