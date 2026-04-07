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

    public static boolean prepareRequest(BooleanSupplier shouldContinue, RateLimiter rateLimiter) {
        if (!canContinue(shouldContinue)) {
            return false;
        }

        if (rateLimiter != null && !rateLimiter.waitBeforeRequest()) {
            return false;
        }

        return canContinue(shouldContinue);
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
