package com.bypassfuzzer.burp.testsupport;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.lang.reflect.Proxy;
import java.util.Collections;

public final class HttpRequestTestFactory {

    private HttpRequestTestFactory() {
    }

    public static HttpRequest request(String path, String query, String method, String contentType, String body) {
        ByteArray byteArray = byteArray(body.length());

        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "path" -> path;
                case "pathWithoutQuery" -> RequestPathUtils.pathWithoutQuery(path);
                case "query" -> query;
                case "method" -> method;
                case "headerValue" -> "Content-Type".equals(args[0]) ? contentType : null;
                case "bodyToString" -> body;
                case "body" -> byteArray;
                case "url" -> "https://example.com" + path;
                case "withMethod" -> request(path, query, (String) args[0], contentType, body);
                case "withUpdatedHeader" -> request(path, query, method, (String) args[1], body);
                case "withBody" -> request(path, query, method, contentType, (String) args[0]);
                case "withPath" -> {
                    String updatedPath = (String) args[0];
                    yield request(updatedPath, RequestPathUtils.queryFromPath(updatedPath), method, contentType, body);
                }
                case "toString" -> method + " " + path;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    private static ByteArray byteArray(int length) {
        return (ByteArray) Proxy.newProxyInstance(
            ByteArray.class.getClassLoader(),
            new Class<?>[]{ByteArray.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "length" -> length;
                case "iterator" -> Collections.<Byte>emptyIterator();
                case "toString" -> "";
                default -> defaultValue(invokedMethod.getReturnType());
            }
        );
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == long.class) {
            return 0L;
        }
        if (returnType == short.class) {
            return (short) 0;
        }
        return null;
    }
}
