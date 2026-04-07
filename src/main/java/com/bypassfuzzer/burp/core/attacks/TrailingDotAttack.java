package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;

import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class TrailingDotAttack implements AttackStrategy {

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter, AttackExecutor attackExecutor) {
        if (!AttackExecutionSupport.logStart(api, "Starting Trailing Dot Attack")) {
            return;
        }

        if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Trailing Dot Attack stopped before execution")) {
            return;
        }

        try {
            String host = baseRequest.httpService().host();
            String hostWithDot = host + ".";
            HttpRequest modifiedRequest = baseRequest.withUpdatedHeader("Host", hostWithDot);
            if (!attackExecutor.execute(getAttackType(), "Host: " + hostWithDot, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                return;
            }
            AttackExecutionSupport.logOutput(api, "Trailing Dot Attack completed: 1 result sent");
        } catch (Exception e) {
            if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Trailing dot attack error: ", e)) {
                return;
            }
        }
    }

    @Override
    public String getAttackType() {
        return "TrailingDot";
    }
}
