package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.PayloadRepository;
import com.bypassfuzzer.burp.http.CookieHeaderUtils;

import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Cookie-based debug parameter injection attack.
 * Injects debug/admin parameters via the Cookie header to bypass access controls.
 */
public class CookieParamAttack implements AttackStrategy {

    private static final String ATTACK_TYPE = "Cookie";
    private static final String EXISTING_COOKIE_TYPE = "Cookie (Existing)";
    private static final String[] FUZZ_VALUES = {
        "true", "1", "yes", "on", "admin", "root", "false", "0", "no", "off"
    };

    private final boolean fuzzExistingCookies;
    private final PayloadRepository payloadRepository;

    public CookieParamAttack(boolean fuzzExistingCookies) {
        this(fuzzExistingCookies, new PayloadRepository());
    }

    CookieParamAttack(boolean fuzzExistingCookies, PayloadRepository payloadRepository) {
        this.fuzzExistingCookies = fuzzExistingCookies;
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

        if (fuzzExistingCookies) {
            fuzzExistingCookies(api, originalRequest, resultCallback, isRunning, rateLimiter, attackExecutor);
        }

        executeNewCookieAttacks(
            api,
            originalRequest,
            payloadRepository.loadParamPayloads(),
            resultCallback,
            isRunning,
            rateLimiter,
            attackExecutor
        );
    }

    private void fuzzExistingCookies(MontoyaApi api, HttpRequest originalRequest,
                                     Consumer<AttackResult> resultCallback, BooleanSupplier isRunning,
                                     RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        String existingCookie = originalRequest.headerValue("Cookie");
        if (existingCookie == null || existingCookie.isEmpty()) {
            return;
        }

        Map<String, String> cookies = CookieHeaderUtils.parse(existingCookie);
        if (cookies.isEmpty()) {
            return;
        }

        for (String cookieName : cookies.keySet()) {
            for (String fuzzValue : FUZZ_VALUES) {
                if (!isRunning.getAsBoolean()) {
                    return;
                }

                try {
                    HttpRequest modifiedRequest = originalRequest.withUpdatedHeader(
                        "Cookie",
                        CookieHeaderUtils.replaceValue(existingCookie, cookieName, fuzzValue)
                    );
                    if (!attackExecutor.execute(
                        EXISTING_COOKIE_TYPE,
                        cookieName + "=" + fuzzValue,
                        modifiedRequest,
                        resultCallback,
                        isRunning,
                        rateLimiter
                    )) {
                        return;
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error fuzzing existing cookie '" + cookieName + "': " + e.getMessage());
                }
            }
        }
    }

    private void executeNewCookieAttacks(MontoyaApi api, HttpRequest originalRequest,
                                         List<String> paramPayloads, Consumer<AttackResult> resultCallback,
                                         BooleanSupplier isRunning, RateLimiter rateLimiter,
                                         AttackExecutor attackExecutor) {

        String existingCookie = originalRequest.headerValue("Cookie");

        for (String param : paramPayloads) {
            if (!isRunning.getAsBoolean()) {
                break;
            }

            try {
                HttpRequest modifiedRequest = existingCookie != null && !existingCookie.isEmpty()
                    ? originalRequest.withUpdatedHeader("Cookie", CookieHeaderUtils.upsertCookie(existingCookie, param))
                    : originalRequest.withAddedHeader("Cookie", param);

                if (!attackExecutor.execute(ATTACK_TYPE, param, modifiedRequest, resultCallback, isRunning, rateLimiter)) {
                    break;
                }
            } catch (Exception e) {
                api.logging().logToError("Error in cookie param attack with payload '" + param + "': " + e.getMessage());
            }
        }
    }
}
