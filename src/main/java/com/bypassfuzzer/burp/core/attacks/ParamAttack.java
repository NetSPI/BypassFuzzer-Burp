package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.PayloadRepository;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Debug parameter injection attack.
 * Appends debug/admin query parameters to bypass access controls.
 */
public class ParamAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Param";
    private static final String EXISTING_PARAM_TYPE = "Param (Existing)";
    private static final String[] FUZZ_VALUES = {
        "true", "1", "yes", "on", "admin", "root", "false", "0", "no", "off"
    };

    private final PayloadRepository payloadRepository;

    public ParamAttack() {
        this(new PayloadRepository());
    }

    ParamAttack(PayloadRepository payloadRepository) {
        this.payloadRepository = payloadRepository;
    }

    @Override
    public String getAttackType() {
        return ATTACK_TYPE;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest originalRequest, String targetUrl,
                        Consumer<AttackResult> resultCallback, BooleanSupplier isRunning,
                        RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        String basePath = RequestPathUtils.extractPathAndQuery(targetUrl);
        if (!fuzzExistingUrlParams(api, originalRequest, basePath, resultCallback, isRunning, rateLimiter, attackExecutor)) {
            return;
        }

        executeUrlParamAttacks(
            api,
            originalRequest,
            basePath,
            payloadRepository.loadParamPayloads(),
            resultCallback,
            isRunning,
            rateLimiter,
            attackExecutor
        );
    }

    private boolean fuzzExistingUrlParams(MontoyaApi api, HttpRequest originalRequest, String basePath,
                                          Consumer<AttackResult> resultCallback, BooleanSupplier isRunning,
                                          RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        List<String> existingParamNames = QueryStringUtils.parseDecodedParameters(RequestPathUtils.queryFromPath(basePath)).stream()
            .map(QueryStringUtils.QueryParameter::name)
            .distinct()
            .toList();
        if (existingParamNames.isEmpty()) {
            return true;
        }

        for (String paramName : existingParamNames) {
            for (String fuzzValue : FUZZ_VALUES) {
                if (!AttackExecutionSupport.canContinue(isRunning)) {
                    return false;
                }

                try {
                    String modifiedPath = QueryStringUtils.replaceValue(basePath, paramName, fuzzValue);
                    HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);
                    if (!attackExecutor.execute(
                        EXISTING_PARAM_TYPE,
                        paramName + "=" + fuzzValue,
                        modifiedRequest,
                        resultCallback,
                        isRunning,
                        rateLimiter
                    )) {
                        return false;
                    }
                } catch (Exception e) {
                    if (!AttackExecutionSupport.handleExecutionException(
                        api,
                        isRunning,
                        "Error fuzzing existing URL param '" + paramName + "' with value '" + fuzzValue + "': ",
                        e
                    )) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    private void executeUrlParamAttacks(MontoyaApi api, HttpRequest originalRequest, String basePath,
                                        List<String> paramPayloads, Consumer<AttackResult> resultCallback,
                                        BooleanSupplier isRunning, RateLimiter rateLimiter,
                                        AttackExecutor attackExecutor) {

        for (String param : paramPayloads) {
            if (!AttackExecutionSupport.canContinue(isRunning)) {
                return;
            }

            try {
                String modifiedPath = QueryStringUtils.upsertParameter(basePath, param);
                HttpRequest modifiedRequest = originalRequest.withPath(modifiedPath);
                if (!attackExecutor.execute(ATTACK_TYPE, param, modifiedRequest, resultCallback, isRunning, rateLimiter)) {
                    return;
                }
            } catch (Exception e) {
                if (!AttackExecutionSupport.handleExecutionException(
                    api,
                    isRunning,
                    "Error in param attack with payload '" + param + "': ",
                    e
                )) {
                    return;
                }
            }
        }
    }
}
