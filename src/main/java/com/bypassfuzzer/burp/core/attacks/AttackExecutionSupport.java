package com.bypassfuzzer.burp.core.attacks;

import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.function.BooleanSupplier;

/**
 * Shared execution helpers for attack loops.
 */
public final class AttackExecutionSupport {

    private AttackExecutionSupport() {
    }

    public static boolean prepareRequest(BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        if (!shouldContinue.getAsBoolean()) {
            return false;
        }

        if (rateLimiter != null && !rateLimiter.waitBeforeRequest()) {
            return false;
        }

        return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted();
    }
}
