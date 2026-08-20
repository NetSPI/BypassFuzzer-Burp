package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.attacks.AttackExecutionResult;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackRegistry;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.attacks.RegisteredAttack;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.http.RequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Adapts the complete Bypass attack catalog into non-sending Sweep probes. */
final class FullBypassSweepProbeGenerator {

    private final MontoyaApi api;
    private final AttackRegistry attackRegistry;
    private final TargetUrlResolver targetUrlResolver;

    FullBypassSweepProbeGenerator(MontoyaApi api) {
        this(api, new AttackRegistry(), new TargetUrlResolver());
    }

    FullBypassSweepProbeGenerator(MontoyaApi api, AttackRegistry attackRegistry,
                                  TargetUrlResolver targetUrlResolver) {
        this.api = api;
        this.attackRegistry = attackRegistry;
        this.targetUrlResolver = targetUrlResolver;
    }

    List<CoverageSweepProbe> buildProbes(HttpRequest request, boolean includeControl) {
        if (request == null) {
            return List.of();
        }

        List<CoverageSweepProbe> probes = new ArrayList<>();
        if (includeControl) {
            probes.add(new CoverageSweepProbe("Control: original blocked request", "Control", request));
        }

        String targetUrl;
        try {
            targetUrl = targetUrlResolver.resolve(request);
        } catch (IllegalArgumentException e) {
            return List.copyOf(probes);
        }

        FuzzerConfig config = new FuzzerConfig();
        config.setEnableCollaboratorPayloads(
            config.isEnableCollaboratorPayloads() && CollaboratorSupport.isAvailable(api));
        CapturingAttackExecutor executor = new CapturingAttackExecutor(probes);
        BooleanSupplier shouldContinue = () -> !Thread.currentThread().isInterrupted();
        Consumer<AttackResult> ignoredResults = result -> { };

        for (RegisteredAttack attack : attackRegistry.buildEnabledAttacks(config, targetUrl)) {
            if (!shouldContinue.getAsBoolean()) {
                break;
            }
            try {
                attack.strategy().execute(api, request, targetUrl, ignoredResults,
                    shouldContinue, null, executor);
            } catch (Exception e) {
                try {
                    api.logging().logToError("Unable to prepare " + attack.type().displayName()
                        + " Sweep probes: " + e.getMessage());
                } catch (Exception ignored) {
                    // Continue preparing the remaining families if logging is unavailable.
                }
            }
        }
        return List.copyOf(probes);
    }

    private static final class CapturingAttackExecutor extends AttackExecutor {
        private final List<CoverageSweepProbe> probes;

        private CapturingAttackExecutor(List<CoverageSweepProbe> probes) {
            super(new NoOpRequestSender());
            this.probes = probes;
        }

        @Override
        public boolean execute(String attackType, String payload, HttpRequest request,
                               Consumer<AttackResult> resultCallback,
                               BooleanSupplier shouldContinue, HostThrottleCoordinator rateLimiter) {
            return capture(attackType, payload, request, null, shouldContinue);
        }

        @Override
        public boolean execute(String attackType, String payload, HttpRequest request,
                               Consumer<AttackResult> resultCallback,
                               BooleanSupplier shouldContinue, HostThrottleCoordinator rateLimiter,
                               HttpMode httpMode) {
            return capture(attackType, payload, request, httpMode, shouldContinue);
        }

        @Override
        public boolean execute(String attackType, String payload, String targetLabel,
                               String payloadFamily, String payloadEncoding, HttpRequest request,
                               Consumer<AttackResult> resultCallback,
                               BooleanSupplier shouldContinue, HostThrottleCoordinator rateLimiter) {
            return capture(attackType, payload, request, null, shouldContinue);
        }

        @Override
        public AttackExecutionResult executeWithTimeout(String attackType, String payload,
                                                        HttpRequest request,
                                                        Consumer<AttackResult> resultCallback,
                                                        BooleanSupplier shouldContinue,
                                                        HostThrottleCoordinator rateLimiter, long timeout,
                                                        TimeUnit timeUnit) {
            return capture(attackType, payload, request, null, shouldContinue)
                ? AttackExecutionResult.timedOut()
                : AttackExecutionResult.stopped();
        }

        private boolean capture(String attackType, String payload, HttpRequest request,
                                HttpMode httpMode, BooleanSupplier shouldContinue) {
            if (request == null || shouldContinue == null || !shouldContinue.getAsBoolean()
                || Thread.currentThread().isInterrupted()) {
                return false;
            }
            probes.add(new CoverageSweepProbe(payload, attackType, request, httpMode));
            return true;
        }
    }

    private static final class NoOpRequestSender implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return null;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return null;
        }
    }
}
