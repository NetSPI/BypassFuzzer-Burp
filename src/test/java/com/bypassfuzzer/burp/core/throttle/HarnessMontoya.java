package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.lang.reflect.Proxy;

/**
 * Minimal Montoya {@link HttpRequest}/{@link HttpResponse} shims for the live harness, built with
 * reflective proxies so the harness can drive the real {@link HostThrottleCoordinator} outside Burp.
 * Only the members the coordinator touches are implemented: {@code request.url()} (for host keying)
 * and {@code response.statusCode()} / {@code response.headerValue("Retry-After")}.
 */
final class HarnessMontoya {

    private HarnessMontoya() {}

    static HttpRequest request(String url) {
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "url" -> url;
                case "toString" -> url;
                case "hashCode" -> url.hashCode();
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
    }

    static HttpResponse response(int statusCode, String retryAfter) {
        return (HttpResponse) Proxy.newProxyInstance(
            HttpResponse.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "statusCode" -> (short) statusCode;
                case "headerValue" -> args != null && args.length == 1
                    && "Retry-After".equalsIgnoreCase(String.valueOf(args[0])) ? retryAfter : null;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
            });
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) return false;
        if (returnType == byte.class) return (byte) 0;
        if (returnType == short.class) return (short) 0;
        if (returnType == int.class) return 0;
        if (returnType == long.class) return 0L;
        return null;
    }
}
