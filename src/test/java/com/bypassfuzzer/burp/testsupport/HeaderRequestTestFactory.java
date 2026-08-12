package com.bypassfuzzer.burp.testsupport;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Test request proxy that preserves duplicate header names and insertion order. */
public final class HeaderRequestTestFactory {

    private HeaderRequestTestFactory() {
    }

    @SafeVarargs
    public static HttpRequest request(Map.Entry<String, String>... headers) {
        return request("GET", "/admin", "", List.of(headers));
    }

    public static HttpRequest request(String method, String path, String body,
                                      List<Map.Entry<String, String>> headers) {
        List<Map.Entry<String, String>> copy = headers.stream()
            .map(entry -> Map.entry(entry.getKey(), entry.getValue()))
            .toList();
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(), new Class<?>[]{HttpRequest.class},
            (proxy, invoked, args) -> switch (invoked.getName()) {
                case "method" -> method;
                case "path", "pathWithoutQuery" -> path;
                case "query" -> "";
                case "bodyToString" -> body;
                case "body" -> byteArray(body.length());
                case "httpService" -> service();
                case "httpVersion" -> "HTTP/1.1";
                case "url" -> "https://example.com" + path;
                case "headers" -> headerObjects(copy);
                case "headerValue" -> firstValue(copy, (String) args[0]);
                case "hasHeader" -> firstValue(copy, (String) args[0]) != null;
                case "withRemovedHeader" -> request(method, path, body,
                    copy.stream().filter(entry -> !entry.getKey().equalsIgnoreCase((String) args[0])).toList());
                case "withAddedHeader" -> request(method, path, body,
                    appended(copy, (String) args[0], (String) args[1]));
                case "withUpdatedHeader", "withHeader" -> request(method, path, body,
                    appended(copy.stream().filter(entry -> !entry.getKey().equalsIgnoreCase((String) args[0])).toList(),
                        (String) args[0], (String) args[1]));
                case "withMethod" -> request((String) args[0], path, body, copy);
                case "withPath" -> request(method, (String) args[0], body, copy);
                case "withBody" -> request(method, path, String.valueOf(args[0]), copy);
                case "toString" -> raw(method, path, body, copy);
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(invoked.getReturnType());
            }
        );
    }

    public static List<String> values(HttpRequest request, String name) {
        return request.headers().stream().filter(header -> header.name().equalsIgnoreCase(name))
            .map(HttpHeader::value).toList();
    }

    private static List<Map.Entry<String, String>> appended(List<Map.Entry<String, String>> headers,
                                                             String name, String value) {
        List<Map.Entry<String, String>> updated = new ArrayList<>(headers);
        updated.add(Map.entry(name, value));
        return List.copyOf(updated);
    }

    private static String firstValue(List<Map.Entry<String, String>> headers, String name) {
        return headers.stream().filter(entry -> entry.getKey().equalsIgnoreCase(name))
            .map(Map.Entry::getValue).findFirst().orElse(null);
    }

    private static List<HttpHeader> headerObjects(List<Map.Entry<String, String>> headers) {
        return headers.stream().map(entry -> (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(), new Class<?>[]{HttpHeader.class},
            (proxy, invoked, args) -> switch (invoked.getName()) {
                case "name" -> entry.getKey();
                case "value" -> entry.getValue();
                case "toString" -> entry.getKey() + ": " + entry.getValue();
                default -> defaultValue(invoked.getReturnType());
            })).toList();
    }

    private static String raw(String method, String path, String body,
                              List<Map.Entry<String, String>> headers) {
        StringBuilder raw = new StringBuilder(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        headers.forEach(entry -> raw.append(entry.getKey()).append(": ").append(entry.getValue()).append("\r\n"));
        return raw.append("\r\n").append(body).toString();
    }

    private static HttpService service() {
        return (HttpService) Proxy.newProxyInstance(HttpService.class.getClassLoader(),
            new Class<?>[]{HttpService.class}, (proxy, invoked, args) -> switch (invoked.getName()) {
                case "host", "ipAddress" -> "example.com";
                case "port" -> 443;
                case "secure" -> true;
                default -> defaultValue(invoked.getReturnType());
            });
    }

    private static ByteArray byteArray(int length) {
        return (ByteArray) Proxy.newProxyInstance(ByteArray.class.getClassLoader(),
            new Class<?>[]{ByteArray.class}, (proxy, invoked, args) -> switch (invoked.getName()) {
                case "length" -> length;
                case "iterator" -> Collections.<Byte>emptyIterator();
                default -> defaultValue(invoked.getReturnType());
            });
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == short.class) return (short) 0;
        if (type == long.class) return 0L;
        return null;
    }
}
