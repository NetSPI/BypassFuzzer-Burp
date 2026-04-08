package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.RawRequestMutationSupport;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class IdorRequestMutatorTest {

    @Test
    void countOccurrencesIncludesPathHeadersAndBody() {
        HttpRequest request = rawRequest("""
            GET /users/123 HTTP/1.1\r
            Host: example.com\r
            X-Resource: 123\r
            Content-Length: 6\r
            \r
            id=123\
            """);

        IdorRequestMutator mutator = new IdorRequestMutator();

        assertEquals(3, mutator.countOccurrences(request, "123"));
    }

    @Test
    void replaceIdentifierUpdatesContentLengthWhenBodyChanges() {
        RecordingRebuilder rebuilder = new RecordingRebuilder();
        HttpRequest request = rawRequest("""
            POST /users/123 HTTP/1.1\r
            Host: example.com\r
            Content-Type: application/x-www-form-urlencoded\r
            Content-Length: 6\r
            \r
            id=123\
            """);

        IdorRequestMutator mutator = new IdorRequestMutator(rebuilder);
        HttpRequest updated = mutator.replaceIdentifier(request, "123", "987654");

        assertSame(request.httpService(), updated.httpService());
        assertEquals("""
            POST /users/987654 HTTP/1.1\r
            Host: example.com\r
            Content-Type: application/x-www-form-urlencoded\r
            Content-Length: 9\r
            \r
            id=987654\
            """, rebuilder.lastRawRequest);
    }

    @Test
    void replaceIdentifierReturnsOriginalRequestWhenIdentifierIsMissing() {
        RecordingRebuilder rebuilder = new RecordingRebuilder();
        HttpRequest request = rawRequest("""
            GET /users/123 HTTP/1.1\r
            Host: example.com\r
            \r
            """);

        IdorRequestMutator mutator = new IdorRequestMutator(rebuilder);
        HttpRequest updated = mutator.replaceIdentifier(request, "999", "222");

        assertSame(request, updated);
        assertNull(rebuilder.lastRawRequest);
    }

    private static HttpRequest rawRequest(String rawRequest) {
        HttpService service = (HttpService) Proxy.newProxyInstance(
            HttpService.class.getClassLoader(),
            new Class<?>[]{HttpService.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "host" -> "example.com";
                case "port" -> 443;
                case "secure" -> true;
                case "ipAddress" -> "example.com";
                case "toString" -> "https://example.com";
                default -> defaultValue(method.getReturnType());
            }
        );

        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "httpService" -> service;
                case "toString" -> rawRequest;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> defaultValue(method.getReturnType());
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

    private static final class RecordingRebuilder implements RawRequestMutationSupport.RequestRebuilder {
        private String lastRawRequest;

        @Override
        public HttpRequest rebuild(HttpService service, String rawRequest) {
            lastRawRequest = rawRequest;
            return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "httpService" -> service;
                    case "toString" -> rawRequest;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> defaultValue(method.getReturnType());
                }
            );
        }
    }
}
