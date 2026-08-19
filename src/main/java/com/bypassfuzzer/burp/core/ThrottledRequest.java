package com.bypassfuzzer.burp.core;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Lightweight holder for a request that received a throttle response and needs retry.
 * The payload never made it through, so the request must be replayed.
 */
public record ThrottledRequest(
    HttpRequest request,
    String attackType,
    String payload,
    String targetLabel,
    String payloadFamily,
    String payloadEncoding,
    int retryCount
) {

    public ThrottledRequest withIncrementedRetry() {
        return new ThrottledRequest(request, attackType, payload, targetLabel,
            payloadFamily, payloadEncoding, retryCount + 1);
    }
}
