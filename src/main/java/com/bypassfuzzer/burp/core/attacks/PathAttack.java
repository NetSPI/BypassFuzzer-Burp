package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;
import com.bypassfuzzer.burp.core.payloads.UrlPayloadProcessor;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class PathAttack implements AttackStrategy {
    private final List<String> pathPayloads;

    public PathAttack(String targetUrl) {
        List<String> payloads;
        try {
            List<String> urlPayloads = PayloadLoader.loadPayloads("url_payloads.txt");
            UrlPayloadProcessor processor = new UrlPayloadProcessor(targetUrl);
            payloads = processor.generateUrlPayloads(urlPayloads);
        } catch (Exception e) {
            payloads = new ArrayList<>();
        }
        this.pathPayloads = payloads;
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue, RateLimiter rateLimiter, AttackExecutor attackExecutor) {
        // Check if original request is just root path
        String originalPath = extractPath(targetUrl);
        AttackExecutionSupport.logOutput(api, "Path Attack: Checking path from URL '" + targetUrl + "' -> extracted path: '" + originalPath + "'");
        if ("/".equals(originalPath)) {
            AttackExecutionSupport.logOutput(api, "Path Attack: Skipped - original path is root '/' (path manipulation attacks are less effective on root paths - consider testing a deeper endpoint)");
            return;
        }

        if (!AttackExecutionSupport.logStart(api, "Starting Path Attack: " + pathPayloads.size() + " payloads")) {
            return;
        }

        int count = 0;
        for (String modifiedUrl : pathPayloads) {
            if (AttackExecutionSupport.stopIfRequested(
                api,
                shouldContinue,
                "Path Attack stopped by user (" + count + " of " + pathPayloads.size() + " completed)"
            )) {
                return;
            }

            try {
                // Log progress every 50 requests to avoid spam
                if (count % 50 == 0 && pathPayloads.size() > 50) {
                    AttackExecutionSupport.logOutput(api, "Path Attack progress: " + count + " of " + pathPayloads.size() + " requests sent");
                }

                HttpRequest modifiedRequest = baseRequest.withPath(extractPath(modifiedUrl));
                if (!attackExecutor.execute(getAttackType(), modifiedUrl, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                    return;
                }
                count++;
            } catch (Exception e) {
                if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Path attack error with URL: " + modifiedUrl + " - ", e)) {
                    return;
                }
            }
        }

        AttackExecutionSupport.logOutput(api, "Path Attack completed: " + count + " results sent");
    }

    private String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    @Override
    public String getAttackType() {
        return "Path";
    }
}
