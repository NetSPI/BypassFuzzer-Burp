package com.bypassfuzzer.burp.core.attacks;

import com.bypassfuzzer.burp.core.RateLimiter;
import burp.api.montoya.MontoyaApi;

import java.util.function.BooleanSupplier;

/**
 * Shared execution helpers for attack loops.
 */
public final class AttackExecutionSupport {

    private AttackExecutionSupport() {
    }

    /**
     * Checks cancellation and waits for the rate limiter.
     *
     * @return the epoch from the rate limiter (>= 0 on success, 0 when no limiter),
     *         or -1 on failure (interrupted / cancelled).
     */
    public static long prepareRequest(BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        if (!canContinue(shouldContinue)) {
            return -1;
        }

        if (rateLimiter != null) {
            long epoch = rateLimiter.waitBeforeRequest();
            if (epoch < 0) {
                return -1;
            }
            if (!canContinue(shouldContinue)) {
                return -1;
            }
            return epoch;
        }

        return canContinue(shouldContinue) ? 0 : -1;
    }

    public static boolean canContinue(BooleanSupplier shouldContinue) {
        return shouldContinue.getAsBoolean() && !Thread.currentThread().isInterrupted();
    }

    public static boolean logStart(MontoyaApi api, String message) {
        try {
            api.logging().logToOutput(message);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void logOutput(MontoyaApi api, String message) {
        try {
            api.logging().logToOutput(message);
        } catch (Exception e) {
            // Ignore logging failures during attack execution.
        }
    }

    public static void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {
            // Ignore logging failures during attack execution.
        }
    }

    public static boolean stopIfRequested(MontoyaApi api, BooleanSupplier shouldContinue, String stopMessage) {
        if (canContinue(shouldContinue)) {
            return false;
        }

        logOutput(api, stopMessage);
        return true;
    }

    public static boolean handleExecutionException(MontoyaApi api, BooleanSupplier shouldContinue, String messagePrefix, Exception exception) {
        if (!canContinue(shouldContinue)) {
            return false;
        }

        logError(api, messagePrefix + exception.getMessage());
        return true;
    }
}
