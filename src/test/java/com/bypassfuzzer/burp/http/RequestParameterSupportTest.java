package com.bypassfuzzer.burp.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestParameterSupportTest {

    @Test
    void extractsCombinedParametersFromUrlEncodedBodyBeforeQuery() {
        HttpRequest request = request("/admin?debug=query", "debug=query", "POST", "application/x-www-form-urlencoded", "debug=body&role=admin");

        assertEquals(Map.of("debug", "body", "role", "admin"), RequestParameterSupport.extractCombinedParameters(request));
    }

    @Test
    void extractsLocatedParametersFromQueryAndBody() {
        HttpRequest request = request("/admin?debug=1", "debug=1", "POST", "application/json", "{\"role\":\"admin\"}");

        List<LocatedParameter> params = RequestParameterSupport.extractLocatedParameters(request);

        assertTrue(params.contains(new LocatedParameter("debug", "1", ParameterLocation.QUERY)));
        assertTrue(params.contains(new LocatedParameter("role", "admin", ParameterLocation.BODY)));
    }

    @Test
    void appliesJsonBodyFormat() {
        HttpRequest request = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=true");

        HttpRequest updated = RequestParameterSupport.applyBodyFormat(
            request,
            Map.of("debug", "true", "role", "admin"),
            RequestBodyFormat.JSON
        );

        assertEquals("application/json", updated.headerValue("Content-Type"));
        assertTrue(updated.bodyToString().contains("\"debug\":\"true\""));
        assertTrue(updated.bodyToString().contains("\"role\":\"admin\""));
    }

    @Test
    void replacesQueryAndBodyParameters() {
        HttpRequest queryRequest = request("/admin?debug=1&role=user", "debug=1&role=user", "GET", null, "");
        HttpRequest renamedQuery = RequestParameterSupport.replaceParameterName(
            queryRequest,
            new LocatedParameter("debug", "1", ParameterLocation.QUERY),
            "trace"
        );
        HttpRequest updatedQuery = RequestParameterSupport.replaceParameterValue(
            renamedQuery,
            new LocatedParameter("trace", "1", ParameterLocation.QUERY),
            "true"
        );

        assertEquals("/admin?trace=true&role=user", updatedQuery.path());

        HttpRequest bodyRequest = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=1&role=user");

        HttpRequest renamedBody = RequestParameterSupport.replaceParameterName(
            bodyRequest,
            new LocatedParameter("debug", "1", ParameterLocation.BODY),
            "trace"
        );
        HttpRequest updatedBody = RequestParameterSupport.replaceParameterValue(
            renamedBody,
            new LocatedParameter("trace", "1", ParameterLocation.BODY),
            "true"
        );

        assertEquals("trace=true&role=user", updatedBody.bodyToString());
    }

    @Test
    void movesParametersBetweenQueryAndBody() {
        HttpRequest queryRequest = request("/admin?debug=1&role=user", "debug=1&role=user", "GET", null, "");
        HttpRequest movedToBody = RequestParameterSupport.moveQueryToBody(queryRequest, "POST");
        assertEquals("/admin", movedToBody.path());
        assertEquals("debug=1&role=user", movedToBody.bodyToString());

        HttpRequest bodyRequest = request("/admin", "", "POST", "application/x-www-form-urlencoded", "debug=1&role=user");
        HttpRequest movedToQuery = RequestParameterSupport.moveBodyToQuery(bodyRequest, "GET", bodyRequest.bodyToString());

        assertEquals("/admin?debug=1&role=user", movedToQuery.path());
        assertEquals("", movedToQuery.bodyToString());
    }

    private HttpRequest request(String path, String query, String method, String contentType, String body) {
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

    private ByteArray byteArray(int length) {
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

    private Object defaultValue(Class<?> returnType) {
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
