package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Encoding attack strategy.
 * Tests various encoding schemes on path and parameters to bypass security controls.
 */
public class EncodingAttack implements AttackStrategy {

    private static final String[] ENCODING_TYPES = {
        "url",
        "double-url",
        "triple-url",
        "unicode",
        "unicode-long",
        "unicode-overflow"
    };
    private static final int MAX_PATH_LENGTH = 50;
    private static final int MAX_PARAM_LENGTH = 100;
    private static final int MAX_VARIATIONS_PER_STRING = 5;

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl,
                        Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue,
                        RateLimiter rateLimiter, AttackExecutor attackExecutor) {

        if (!AttackExecutionSupport.logStart(api, "Starting Encoding Attack")) {
            return;
        }

        int count = 0;
        Random random = new Random();
        String path = RequestPathUtils.extractPath(targetUrl);

        if ("/".equals(path)) {
            AttackExecutionSupport.logError(api, "Encoding Attack: Skipped - original path is root '/' (encoding attacks are less effective on root paths)");
            return;
        }

        if (path.length() > MAX_PATH_LENGTH) {
            AttackExecutionSupport.logError(api, "Encoding Attack: Skipped - path too long (" + path.length() + " chars, max " + MAX_PATH_LENGTH + ")");
            return;
        }

        AttackExecutionSupport.logOutput(api, "Encoding Attack: Testing " + ENCODING_TYPES.length + " encoding types on path and parameters");

        for (String encodingType : ENCODING_TYPES) {
            if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Encoding Attack stopped by user (" + count + " completed)")) {
                return;
            }

            for (int variation = 0; variation < MAX_VARIATIONS_PER_STRING; variation++) {
                if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Encoding Attack stopped by user (" + count + " completed)")) {
                    return;
                }

                try {
                    String encodedPath = encodeRandomChars(path, encodingType, random);
                    String fullPath = RequestPathUtils.replaceQuery(encodedPath, baseRequest.query());
                    HttpRequest modifiedRequest = baseRequest.withPath(fullPath);
                    String payload = "Path " + encodingType + " #" + (variation + 1) + ": " + encodedPath;
                    if (!attackExecutor.execute(getAttackType(), payload, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                        return;
                    }
                    count++;
                } catch (Exception e) {
                    if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Encoding attack error: ", e)) {
                        return;
                    }
                }
            }
        }

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(baseRequest);

        try {
            long queryCount = params.stream().filter(param -> !param.isBody()).count();
            long bodyCount = params.stream().filter(LocatedParameter::isBody).count();
            AttackExecutionSupport.logOutput(api, "Encoding Attack: Extracted " + params.size() + " parameters");
            AttackExecutionSupport.logOutput(api, "  Query params: " + queryCount + ", Body params: " + bodyCount);
        } catch (Exception e) {
            // Ignore
        }

        for (String encodingType : ENCODING_TYPES) {
            if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Encoding Attack stopped by user (" + count + " completed)")) {
                return;
            }

            for (LocatedParameter param : params) {
                String paramName = param.name();
                String paramValue = param.value();

                if (paramName.length() > MAX_PARAM_LENGTH || paramValue.length() > MAX_PARAM_LENGTH) {
                    String skipReason = paramName.length() > MAX_PARAM_LENGTH
                        ? "name too long (" + paramName.length() + " chars)"
                        : "value too long (" + paramValue.length() + " chars)";
                    AttackExecutionSupport.logOutput(api, "  Skipping param '" + paramName + "': " + skipReason);
                    continue;
                }

                if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Encoding Attack stopped by user (" + count + " completed)")) {
                    return;
                }

                try {
                    String encodedName = encodeRandomChars(paramName, encodingType, random);
                    HttpRequest modifiedRequest = RequestParameterSupport.replaceParameterName(baseRequest, param, encodedName);
                    String location = param.isBody() ? "body" : "query";
                    String payload = "Param name " + encodingType + " (" + location + "): " + paramName + " → " + encodedName;
                    if (!attackExecutor.execute(getAttackType(), payload, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                        return;
                    }
                    count++;
                } catch (Exception e) {
                    if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Encoding attack error on param name: ", e)) {
                        return;
                    }
                }

                if (AttackExecutionSupport.stopIfRequested(api, shouldContinue, "Encoding Attack stopped by user (" + count + " completed)")) {
                    return;
                }

                try {
                    String encodedValue = encodeRandomChars(paramValue, encodingType, random);
                    HttpRequest modifiedRequest = RequestParameterSupport.replaceParameterValue(baseRequest, param, encodedValue);
                    String location = param.isBody() ? "body" : "query";
                    String payload = "Param value " + encodingType + " (" + location + "): " + paramName + "=" + encodedValue;
                    if (!attackExecutor.execute(getAttackType(), payload, modifiedRequest, resultCallback, shouldContinue, rateLimiter)) {
                        return;
                    }
                    count++;
                } catch (Exception e) {
                    if (!AttackExecutionSupport.handleExecutionException(api, shouldContinue, "Encoding attack error on param value: ", e)) {
                        return;
                    }
                }
            }
        }

        AttackExecutionSupport.logOutput(api, "Encoding Attack completed: " + count + " results sent");
    }

    private String encodeRandomChars(String input, String encodingType, Random random) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        StringBuilder result = new StringBuilder();
        int encodeCount = Math.max(1, input.length() / 3);
        Set<Integer> positionsToEncode = new HashSet<>();
        while (positionsToEncode.size() < encodeCount) {
            positionsToEncode.add(random.nextInt(input.length()));
        }

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (positionsToEncode.contains(i) && isEncodable(c)) {
                result.append(encodeChar(c, encodingType));
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }

    private boolean isEncodable(char c) {
        return (c >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '-'
            || c == '_'
            || c == '.';
    }

    private String encodeChar(char c, String encodingType) {
        return switch (encodingType) {
            case "url" -> String.format("%%%02X", (int) c);
            case "double-url" -> String.format("%%25%02X", (int) c);
            case "triple-url" -> String.format("%%2525%02X", (int) c);
            case "unicode" -> String.format("%%u%04x", (int) c);
            case "unicode-long" -> String.format("\\u%04x", (int) c);
            case "unicode-overflow" -> String.format("%%u%04x", (int) c + (0x4e * 0x100));
            default -> String.valueOf(c);
        };
    }

    @Override
    public String getAttackType() {
        return "Encoding";
    }
}
