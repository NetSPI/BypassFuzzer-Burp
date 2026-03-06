package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.RequestSender;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Executes a prepared request using shared attack-loop semantics.
 */
public class AttackExecutor {

    private final RequestSender requestSender;

    public AttackExecutor(RequestSender requestSender) {
        this.requestSender = requestSender;
    }

    public boolean execute(String attackType, String payload, HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           RateLimiter rateLimiter) {
        if (!AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter)) {
            return false;
        }

        HttpResponse response = requestSender.send(request);
        resultCallback.accept(new AttackResult(attackType, payload, request, response));
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

        HttpResponse response = requestSender.send(request, timeout, timeUnit);
        if (response == null) {
            return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted()
                ? AttackExecutionResult.timedOut()
                : AttackExecutionResult.stopped();
        }

        resultCallback.accept(new AttackResult(attackType, payload, request, response));
        return AttackExecutionResult.executed(response);
    }
}
