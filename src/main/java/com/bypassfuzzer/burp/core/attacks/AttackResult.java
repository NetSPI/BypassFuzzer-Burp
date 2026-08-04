package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Represents the result of a single attack attempt.
 */
public class AttackResult {
    private final String attackType;
    private final String payload;
    private final String targetLabel;
    private final String payloadFamily;
    private final String payloadEncoding;
    private final HttpRequest request;
    private final HttpResponse response;
    private final HttpRequest originalRequest;
    private final HttpResponse originalResponse;
    private final HttpRequest verificationRequest;
    private final HttpResponse verificationResponse;
    private final int statusCode;
    private final int contentLength;
    private final String contentType;
    private final long timestamp;

    public AttackResult(String attackType, String payload, HttpRequest request, HttpResponse response) {
        this(attackType, payload, null, null, null, request, response, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpResponse originalResponse) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            null, originalResponse);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpRequest originalRequest, HttpResponse originalResponse) {
        this(attackType, payload, targetLabel, payloadFamily, payloadEncoding, request, response,
            originalRequest, originalResponse, null, null);
    }

    public AttackResult(String attackType, String payload, String targetLabel, String payloadFamily,
                        String payloadEncoding, HttpRequest request, HttpResponse response,
                        HttpRequest originalRequest, HttpResponse originalResponse,
                        HttpRequest verificationRequest, HttpResponse verificationResponse) {
        this.attackType = attackType;
        this.payload = payload;
        this.targetLabel = targetLabel == null ? "" : targetLabel;
        this.payloadFamily = payloadFamily == null ? "" : payloadFamily;
        this.payloadEncoding = payloadEncoding == null ? "" : payloadEncoding;
        this.request = request;
        this.response = response;
        this.originalRequest = originalRequest;
        this.originalResponse = originalResponse;
        this.verificationRequest = verificationRequest;
        this.verificationResponse = verificationResponse;
        this.statusCode = response != null ? response.statusCode() : 0;
        this.contentLength = response != null ? response.body().length() : 0;
        this.contentType = response != null ? extractContentType(response) : "";
        this.timestamp = System.currentTimeMillis();
    }

    private String extractContentType(HttpResponse response) {
        return response.headers().stream()
            .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
            .map(h -> h.value())
            .findFirst()
            .orElse("");
    }

    public String getAttackType() {
        return attackType;
    }

    public String getPayload() {
        return payload;
    }

    public String getTargetLabel() {
        return targetLabel;
    }

    public String getPayloadFamily() {
        return payloadFamily;
    }

    public String getPayloadEncoding() {
        return payloadEncoding;
    }

    /**
     * Returns the result signal. Coverage Sweep stores its signal in the
     * payload-encoding slot for compatibility with the shared results table.
     */
    public String getSignal() {
        return payloadEncoding;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpResponse getOriginalResponse() {
        return originalResponse;
    }

    public HttpRequest getVerificationRequest() {
        return verificationRequest;
    }

    public HttpResponse getVerificationResponse() {
        return verificationResponse;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getContentLength() {
        return contentLength;
    }

    public String getContentType() {
        return contentType;
    }

    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s -> %d (%d bytes)", attackType, payload, statusCode, contentLength);
    }
}
