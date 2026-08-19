package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.ThrottledRequest;
import com.bypassfuzzer.burp.http.RequestSender;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * Executes a prepared request using shared attack-loop semantics.
 * <p>When a concurrent send pool is configured via {@link #enableConcurrentSends},
 * the HTTP send is submitted to the pool instead of running synchronously.
 * This allows many payloads to be in-flight simultaneously while the
 * {@link RateLimiter} controls admission.</p>
 */
public class AttackExecutor {

    private final RequestSender requestSender;
    private final UnaryOperator<HttpRequest> requestTransformer;
    private volatile ExecutorService sendPool;
    private volatile Semaphore inFlightPermits;
    private volatile int maxInFlight;

    public AttackExecutor(RequestSender requestSender) {
        this(requestSender, UnaryOperator.identity());
    }

    public AttackExecutor(RequestSender requestSender, UnaryOperator<HttpRequest> requestTransformer) {
        this.requestSender = requestSender;
        this.requestTransformer = requestTransformer == null ? UnaryOperator.identity() : requestTransformer;
    }

    /**
     * Enable concurrent HTTP sends. When set, {@code execute()} submits the
     * actual HTTP round-trip to the provided pool instead of blocking the
     * caller. A semaphore bounds the number of in-flight requests.
     */
    public void enableConcurrentSends(ExecutorService pool, int maxInFlight) {
        this.sendPool = pool;
        this.maxInFlight = maxInFlight;
        this.inFlightPermits = new Semaphore(maxInFlight, true);
    }

    /**
     * Wait for all in-flight concurrent sends to complete.
     * Call after all strategies have finished to ensure every response is processed.
     */
    public void awaitInFlight() {
        Semaphore permits = this.inFlightPermits;
        if (permits == null) return;
        try {
            // Acquire all permits -- blocks until every in-flight send releases its permit
            permits.acquire(maxInFlight);
            permits.release(maxInFlight);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
        long epoch = AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter);
        if (epoch < 0) {
            return false;
        }

        HttpRequest sentRequest = requestTransformer.apply(request);

        // Concurrent mode: submit HTTP send to pool, return immediately
        if (sendPool != null && inFlightPermits != null) {
            try {
                inFlightPermits.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            sendPool.submit(() -> {
                try {
                    HttpResponse response = requestSender.send(sentRequest, httpMode);
                    if (rateLimiter != null) {
                        rateLimiter.reportResponse(response, epoch);
                        if (handleSmartThrottleRetry(rateLimiter, response, sentRequest,
                                attackType, payload, null, null, null)) {
                            return;
                        }
                    }
                    resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
                } finally {
                    inFlightPermits.release();
                }
            });
            return true;
        }

        // Sequential mode: send synchronously
        HttpResponse response = requestSender.send(sentRequest, httpMode);
        if (rateLimiter != null) {
            rateLimiter.reportResponse(response, epoch);
            if (handleSmartThrottleRetry(rateLimiter, response, sentRequest,
                    attackType, payload, null, null, null)) {
                return true;
            }
        }
        resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
        return true;
    }

    public boolean execute(String attackType, String payload, String targetLabel, String payloadFamily, String payloadEncoding,
                           HttpRequest request,
                           Consumer<AttackResult> resultCallback,
                           BooleanSupplier shouldContinue,
                           RateLimiter rateLimiter) {
        long epoch = AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter);
        if (epoch < 0) {
            return false;
        }

        HttpRequest sentRequest = requestTransformer.apply(request);

        // Concurrent mode: submit HTTP send to pool, return immediately
        if (sendPool != null && inFlightPermits != null) {
            try {
                inFlightPermits.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            sendPool.submit(() -> {
                try {
                    HttpResponse response = requestSender.send(sentRequest);
                    if (rateLimiter != null) {
                        rateLimiter.reportResponse(response, epoch);
                        if (handleSmartThrottleRetry(rateLimiter, response, sentRequest,
                                attackType, payload, targetLabel, payloadFamily, payloadEncoding)) {
                            return;
                        }
                    }
                    resultCallback.accept(new AttackResult(attackType, payload, targetLabel, payloadFamily,
                        payloadEncoding, sentRequest, response));
                } finally {
                    inFlightPermits.release();
                }
            });
            return true;
        }

        // Sequential mode: send synchronously
        HttpResponse response = requestSender.send(sentRequest);
        if (rateLimiter != null) {
            rateLimiter.reportResponse(response, epoch);
            if (handleSmartThrottleRetry(rateLimiter, response, sentRequest,
                    attackType, payload, targetLabel, payloadFamily, payloadEncoding)) {
                return true;
            }
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
        long epoch = AttackExecutionSupport.prepareRequest(shouldContinue, rateLimiter);
        if (epoch < 0) {
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
            rateLimiter.reportResponse(response, epoch);
            if (handleSmartThrottleRetry(rateLimiter, response, sentRequest,
                    attackType, payload, null, null, null)) {
                return AttackExecutionResult.executed(response);
            }
        }

        resultCallback.accept(new AttackResult(attackType, payload, sentRequest, response));
        return AttackExecutionResult.executed(response);
    }

    /**
     * If smart throttle is enabled and the response is a throttle code, enqueue for retry
     * and suppress the result callback (the payload didn't land).
     *
     * @return true if the request was throttled and queued for retry (caller should NOT deliver result)
     */
    private boolean handleSmartThrottleRetry(RateLimiter rateLimiter, HttpResponse response,
                                              HttpRequest sentRequest, String attackType,
                                              String payload, String targetLabel,
                                              String payloadFamily, String payloadEncoding) {
        if (!rateLimiter.isSmartThrottleEnabled() || response == null) {
            return false;
        }
        if (rateLimiter.isThrottleStatusCode(response.statusCode())) {
            ThrottledRequest throttled = new ThrottledRequest(
                sentRequest, attackType, payload,
                targetLabel == null ? "" : targetLabel,
                payloadFamily == null ? "" : payloadFamily,
                payloadEncoding == null ? "" : payloadEncoding,
                0
            );
            rateLimiter.enqueueForRetry(throttled);
            return true;
        }
        return false;
    }
}
