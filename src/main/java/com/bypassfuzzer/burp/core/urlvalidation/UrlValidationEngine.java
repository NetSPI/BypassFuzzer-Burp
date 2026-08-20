package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.TargetUrlResolver;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;

import java.util.Set;
import java.util.function.Consumer;

/**
 * Threaded execution engine for the URL Validation tab.
 */
public class UrlValidationEngine {

    private final MontoyaApi api;
    private final TargetUrlResolver targetUrlResolver = new TargetUrlResolver();
    private volatile boolean running = false;
    private Thread runnerThread;
    private HostThrottleCoordinator coordinator;

    public UrlValidationEngine(MontoyaApi api) {
        this.api = api;
    }

    public boolean start(HttpRequest request, UrlValidationOptions options, Consumer<AttackResult> resultCallback, Runnable completionCallback) {
        if (running) {
            return false;
        }

        running = true;
        runnerThread = new Thread(() -> {
            try {
                execute(request, options, resultCallback);
            } finally {
                running = false;
                if (completionCallback != null) {
                    completionCallback.run();
                }
            }
        }, "bypassfuzzer-url-validation");
        runnerThread.start();
        return true;
    }

    public void stop() {
        running = false;
        if (runnerThread != null) {
            runnerThread.interrupt();
        }
    }

    public void cleanup() {
        stop();
        if (runnerThread != null && runnerThread.isAlive()) {
            try {
                runnerThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public boolean isRunning() {
        return running;
    }

    private void execute(HttpRequest request, UrlValidationOptions options, Consumer<AttackResult> resultCallback) {
        String targetUrl = targetUrlResolver.resolve(request);
        coordinator = new HostThrottleCoordinator(options.throttleSettings(), api);

        ConfiguredHeaderPolicy headerPolicy = new ConfiguredHeaderPolicy(options.requestHeaders());
        UrlValidationAttack attack = new UrlValidationAttack(options);
        AttackExecutor attackExecutor = new AttackExecutor(
            new MontoyaRequestSender(api), mutated -> headerPolicy.reconcileMutation(request, mutated));
        attack.execute(api, request, targetUrl, result -> {
            if (running) {
                resultCallback.accept(result);
            }
        }, () -> running, coordinator, attackExecutor);
    }
}
