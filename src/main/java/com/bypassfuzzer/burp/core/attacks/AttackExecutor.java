package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.RequestSender;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * Executes a prepared request using shared attack-loop semantics.
 */
public class AttackExecutor {

    private final RequestSender requestSender;
    private final UnaryOperator<HttpRequest> requestTransformer;

    public AttackExecutor(RequestSender requestSender) {
        this(requestSender, UnaryOperator.identity());
    }

    public AttackExecutor(RequestSender requestSender, UnaryOperator<HttpRequest> requestTransformer) {
        this.requestSender = requestSender;
        this.requestTransformer = requestTransformer == null ? UnaryOperator.identity() : requestTransformer;
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           RateLimiter rateLimiter) {
        return execute(attackType, payload, null, null, null, request, resultCallback, shouldContinue, rateLimiter);
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           RateLimiter rateLimiter,
                           HttpMode httpMode) {
        if (!AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter)) {
            return false;
        }

        HttpRequest sentRequest = requestTransformer.apply(request);
        HttpResponse response = requestSender.send(sentRequest, httpMode);
        if (rateLimiter != null) {
            rateLimiter.reportResponse(response);
        }
        resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
        return true;
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily, String payloadEncoding,
                           HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           RateLimiter rateLimiter) {
        if (!AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter)) {
            return false;
        }

        HttpRequest sentRequest = requestTransformer.apply(request);
        HttpResponse response = requestSender.send(sentRequest);
        if (rateLimiter != null) {
            rateLimiter.reportResponse(response);
        }
        resultCallback.accept(new AttackResult(attackType, payload, targetLabel, payloadFamily,
            payloadEncoding, sentRequest, response));
        return true;
    }

    public AttackExecutionResult executeWithTimeout(String attackType, String payload, HttpRequest request,
                                                    Consumer<AttackResult> resultCallback,
                                                    BooleanSupplier shouldContinue,
                                                    RateLimiter rateLimiter,
                                                    long timeout,
                                                    TimeUnit timeUnit) {
        if (!AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter)) {
            return AttackExecutionResult.stopped();
        }

        HttpRequest sentRequest = requestTransformer.apply(request);
        HttpResponse response = requestSender.send(sentRequest, timeout, timeUnit);
        if (response == null) {
            return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted()
                ? AttackExecutionResult.timedOut()
                : AttackExecutionResult.stopped();
        }

        if (rateLimiter != null) {
            rateLimiter.reportResponse(response);
        }

        resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
        return AttackExecutionResult.executed(response);
    }
}
