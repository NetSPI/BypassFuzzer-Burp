package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class ProtocolAttack implements AttackStrategy {
    private static final List<String> HTTP_VERSIONS = Arrays.asList("HTTP/2", "HTTP/1.1", "HTTP/1.0", "HTTP/0.9");
    private static final int REQUEST_TIMEOUT_SECONDS = 5;
    private final RawRequestFactory rawRequestFactory;

    public ProtocolAttack() {
        this((service, rawRequest) -> HttpRequest.httpRequest(service, ByteArray.byteArray(rawRequest)));
    }

    public ProtocolAttack(RawRequestFactory rawRequestFactory) {
        this.rawRequestFactory = rawRequestFactory;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter, AttackExecutor attackExecutor) {
        if (!AttackExecutionSupport.logStart(api, "Starting Protocol Attack")) {
            return;
        }

        for (String version : HTTP_VERSIONS) {
            if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Protocol Attack stopped by user")) {
                return;
            }

            try {
                AttackExecutionSupport.logOutput(api, "Testing protocol: " + version);
                HttpRequest modifiedRequest = buildRequestWithVersion(api, baseRequest, version);
                AttackExecutionResult result = attackExecutor.executeWithTimeout(
                    getAttackType(),
                    "Protocol: " + version,
                    modifiedRequest,
                    resultCallback,
                    shouldContinue,
                    rateLimiter,
                    REQUEST_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
                );

                if (result.outcome() == AttackExecutionOutcome.EXECUTED) {
                    AttackExecutionSupport.logOutput(api, "Protocol " + version + " completed with status: " + result.response().statusCode());
                } else if (result.outcome() == AttackExecutionOutcome.STOPPED) {
                    return;
                } else {
                    AttackExecutionSupport.logOutput(api, "Protocol " + version + " timed out after " + REQUEST_TIMEOUT_SECONDS + " seconds");
                }
            } catch (Exception e) {
                if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Protocol attack error: " + version + " - ", e)) {
                    return;
                }
            }
        }

        AttackExecutionSupport.logOutput(api, "Protocol Attack completed");
    }

    private HttpRequest buildRequestWithVersion(MontoyaApi api, HttpRequest baseRequest, String newVersion) {
        try {
            ByteArray requestBytes = baseRequest.toByteArray();
            String rawRequest = requestBytes.toString();
            int firstLineEnd = rawRequest.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = rawRequest.indexOf("\n");
            }

            if (firstLineEnd > 0) {
                String requestLine = rawRequest.substring(0, firstLineEnd);
                String restOfRequest = rawRequest.substring(firstLineEnd);
                String newRequestLine = requestLine.replaceFirst("HTTP/[0-9.]+", newVersion);
                String newRawRequest = newRequestLine + restOfRequest;

                // Add appropriate headers based on version
                if (newVersion.equals("HTTP/1.0")) {
                    // For HTTP/1.0, ensure Connection: close header exists
                    if (!newRawRequest.toLowerCase().contains("connection:")) {
                        int headerInsertPos = newRawRequest.indexOf("\r\n") + 2;
                        if (headerInsertPos == 1) {
                            headerInsertPos = newRawRequest.indexOf("\n") + 1;
                        }
                        newRawRequest = newRawRequest.substring(0, headerInsertPos) +
                                       "Connection: close\r\n" +
                                       newRawRequest.substring(headerInsertPos);
                    }
                } else if (newVersion.equals("HTTP/2")) {
                    // HTTP/2 cleartext upgrade (h2c)
                    if (!newRawRequest.toLowerCase().contains("upgrade:")) {
                        int headerInsertPos = newRawRequest.indexOf("\r\n") + 2;
                        if (headerInsertPos == 1) {
                            headerInsertPos = newRawRequest.indexOf("\n") + 1;
                        }
                        newRawRequest = newRawRequest.substring(0, headerInsertPos) +
                                       "Upgrade: h2c\r\n" +
                                       "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n" +
                                       newRawRequest.substring(headerInsertPos);
                    }
                }

                AttackExecutionSupport.logOutput(api, "Built " + newVersion + " request: " + newRequestLine);
                return rawRequestFactory.create(baseRequest.httpService(), newRawRequest);
            }
        } catch (Exception e) {
            AttackExecutionSupport.logError(api, "Failed to build " + newVersion + " request: " + e.getMessage());
        }

        return baseRequest;
    }
    @Override
    public String getAttackType() {
        return "Protocol";
    }

    @FunctionalInterface
    public interface RawRequestFactory {
        HttpRequest create(HttpService service, String rawRequest);
    }
}
