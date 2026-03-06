package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.*;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;

import java.util.List;
import java.util.function.Consumer;

/**
 * Main fuzzer engine that orchestrates all attack strategies.
 */
public class FuzzerEngine {

    private final MontoyaApi api;
    private final FuzzerConfig config;
    private volatile boolean running = false;
    private Thread fuzzerThread;
    private RateLimiter rateLimiter;
    private final TargetUrlResolver targetUrlResolver;
    private final AttackRegistry attackRegistry;

    public FuzzerEngine(MontoyaApi api, FuzzerConfig config) {
        this.api = api;
        this.config = config;
        this.targetUrlResolver = new TargetUrlResolver();
        this.attackRegistry = new AttackRegistry();
    }

    /**
     * Start fuzzing with the given request.
     *
     * @param request The HTTP request to fuzz
     * @param resultCallback Callback to handle each result as it comes in
     */
    public boolean startFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback) {
        return startFuzzing(request, resultCallback, null);
    }

    public boolean startFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) {
            safeLog("Fuzzer is already running!");
            return false;
        }

        // Wait for previous thread to finish if it exists
        if (fuzzerThread != null && fuzzerThread.isAlive()) {
            safeLog("Waiting for previous fuzzer thread to complete...");
            try {
                fuzzerThread.join(5000); // Wait up to 5 seconds
                if (fuzzerThread.isAlive()) {
                    safeLog("Previous thread still running, interrupting...");
                    fuzzerThread.interrupt();
                    fuzzerThread.join(2000); // Wait another 2 seconds
                }
            } catch (InterruptedException e) {
                safeLog("Interrupted while waiting for previous thread");
            }
        }

        running = true;

        fuzzerThread = new Thread(() -> {
            try {
                executeFuzzing(request, resultCallback);
            } catch (Exception e) {
                safeLogError("Fuzzer error: " + e.getMessage());
            } finally {
                running = false;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-engine");

        fuzzerThread.start();
        return true;
    }

    /**
     * Stop the fuzzer.
     */
    public void stopFuzzing() {
        if (running && fuzzerThread != null) {
            running = false;
            fuzzerThread.interrupt();
            safeLog("Fuzzer stopped by user");
        }
    }

    /**
     * Check if fuzzer is currently running.
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Cleanup and stop all fuzzing threads gracefully.
     * Called during extension unload.
     */
    public void cleanup() {
        running = false;
        if (fuzzerThread != null && fuzzerThread.isAlive()) {
            fuzzerThread.interrupt();
            try {
                fuzzerThread.join(2000); // Wait up to 2 seconds for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void executeFuzzing(HttpRequest request, Consumer<AttackResult> resultCallback) {
        final String targetUrl;
        try {
            targetUrl = targetUrlResolver.resolve(request);
        } catch (IllegalArgumentException e) {
            safeLog("Error: " + e.getMessage());
            return;
        }

        // Initialize rate limiter
        rateLimiter = new RateLimiter(
            api,
            config.getRequestsPerSecond(),
            config.getThrottleStatusCodes(),
            config.isEnableAutoThrottle()
        );

        safeLog("=== BypassFuzzer Started ===");
        safeLog("Target: " + targetUrl);
        safeLog("Attack types enabled: " + formatEnabledAttackTypes());

        if (config.getRequestsPerSecond() > 0) {
            safeLog("Rate limit: " + config.getRequestsPerSecond() + " requests/second");
        } else {
            safeLog("Rate limit: unlimited");
        }

        if (config.isEnableAutoThrottle() && !config.getThrottleStatusCodes().isEmpty()) {
            safeLog("Auto-throttle enabled for status codes: " + config.getThrottleStatusCodes());
        }

        List<RegisteredAttack> attacks = attackRegistry.buildEnabledAttacks(config, targetUrl);
        AttackExecutor attackExecutor = new AttackExecutor(new MontoyaRequestSender(api));
        safeLog("Built " + attacks.size() + " attack strategies");

        for (RegisteredAttack attack : attacks) {
            if (!running) {
                safeLog("Fuzzer stopped during execution");
                break;
            }

            safeLog("\n=== Executing " + attack.type().displayName() + " Attack ===");

            try {
                // Pass callback and running check to strategy - results sent immediately as they're generated
                attack.strategy().execute(api, request, targetUrl, result -> {
                    if (running) {
                        try {
                            resultCallback.accept(result);
                            // Report response to rate limiter for auto-throttling
                            if (rateLimiter != null) {
                                rateLimiter.reportResponse(result.getStatusCode());
                            }
                        } catch (Exception callbackEx) {
                            safeLogError("Error sending result to UI callback: " + callbackEx.getMessage());
                        }
                    }
                }, () -> running, rateLimiter, attackExecutor);

            } catch (Exception e) {
                safeLogError("Error in " + attack.type().displayName() + " attack: " + e.getMessage());
            }
        }

        safeLog("\n=== BypassFuzzer Completed ===");
    }

    /**
     * Safe logging that handles API being null during extension unload.
     */
    private void safeLog(String message) {
        try {
            if (api != null && api.logging() != null) {
                api.logging().logToOutput(message);
            }
        } catch (Exception e) {
            // API unavailable during unload, ignore
        }
    }

    /**
     * Safe error logging that handles API being null during extension unload.
     */
    private void safeLogError(String message) {
        try {
            if (api != null && api.logging() != null) {
                api.logging().logToError(message);
            }
        } catch (Exception e) {
            // API unavailable during unload, ignore
        }
    }

    private String formatEnabledAttackTypes() {
        return config.getEnabledAttackTypes().stream()
            .map(AttackType::displayName)
            .toList()
            .toString();
    }
}
