package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.attacks.AttackStrategy;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Dedicated URL validation bypass attack strategy.
 */
public class UrlValidationAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "URL Validation";

    private final UrlValidationOptions options;
    private final UrlValidationCandidateFinder candidateFinder;
    private final UrlValidationPayloadGenerator payloadGenerator;

    public UrlValidationAttack(UrlValidationOptions options) {
        this(options, new UrlValidationCandidateFinder(), new UrlValidationPayloadGenerator());
    }

    public UrlValidationAttack(UrlValidationOptions options,
                               UrlValidationCandidateFinder candidateFinder,
                               UrlValidationPayloadGenerator payloadGenerator) {
        this.options = options;
        this.candidateFinder = candidateFinder;
        this.payloadGenerator = payloadGenerator;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback,
                        BooleanSupplier shouldContinue, RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        List<UrlValidationCandidate> candidates = candidateFinder.find(baseRequest, options);
        if (candidates.isEmpty()) {
            logOutput(api, "URL Validation: no URL-bearing sinks found");
            return;
        }

        logOutput(api, "URL Validation: found " + candidates.size() + " candidate sink(s)");

        int count = 0;
        for (UrlValidationCandidate candidate : candidates) {
            if (!shouldContinue.getAsBoolean()) {
                logOutput(api, "URL Validation stopped by user (" + count + " completed)");
                return;
            }

            for (UrlValidationPayload payload : payloadGenerator.generate(candidate, options)) {
                if (!shouldContinue.getAsBoolean()) {
                    logOutput(api, "URL Validation stopped by user (" + count + " completed)");
                    return;
                }

                try {
                    HttpRequest mutatedRequest = candidate.mutator().mutate(baseRequest, payload.value());
                    if (!attackExecutor.execute(
                        getAttackType(),
                        payload.value(),
                        candidate.displayName(),
                        payload.family().displayName(),
                        payload.encoding().label(),
                        mutatedRequest,
                        resultCallback,
                        shouldContinue,
                        rateLimiter
                    )) {
                        return;
                    }
                    count++;
                } catch (Exception e) {
                    logError(api, "URL Validation error on " + candidate.displayName() + ": " + e.getMessage());
                }
            }
        }

        logOutput(api, "URL Validation completed: " + count + " results sent");
    }

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    private void logOutput(MontoyaApi api, String message) {
        try {
            api.logging().logToOutput(message);
        } catch (Exception e) {
            // Ignore logging failures.
        }
    }

    private void logError(MontoyaApi api, String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception e) {
            // Ignore logging failures.
        }
    }
}
