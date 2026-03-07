package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared request-parameter extraction and mutation support for attack strategies.
 */
public final class RequestParameterSupport {

    private RequestParameterSupport() {
    }

    public static boolean supportsBody(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    public static String extractUrlEncodedBody(HttpRequest request) {
        String contentType = request.headerValue("Content-Type");
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")) {
            return null;
        }

        if (request.body() == null || request.body().length() == 0) {
            return null;
        }

        return request.bodyToString();
    }

    public static Map<String, String> extractCombinedParameters(HttpRequest request) {
        Map<String, String> params = new LinkedHashMap<>();

        String contentType = request.headerValue("Content-Type");
        if (contentType != null && request.body() != null && request.body().length() > 0) {
            params.putAll(parseBodyParameters(request.bodyToString(), contentType));
        }

        if (params.isEmpty()) {
            params.putAll(QueryStringUtils.parseDecoded(request.query()));
        }

        return params;
    }

    public static List<LocatedParameter> extractLocatedParameters(HttpRequest request) {
        List<LocatedParameter> params = new ArrayList<>();

        for (QueryStringUtils.QueryParameter parameter : QueryStringUtils.parseRawParameters(request.query())) {
            params.add(new LocatedParameter(parameter.name(), parameter.value(), ParameterLocation.QUERY));
        }

        String contentType = request.headerValue("Content-Type");
        if (contentType != null && request.body() != null && request.body().length() > 0) {
            for (Map.Entry<String, String> entry : parseBodyParameters(request.bodyToString(), contentType).entrySet()) {
                params.add(new LocatedParameter(entry.getKey(), entry.getValue(), ParameterLocation.BODY));
            }
        }

        return params;
    }

    public static HttpRequest prepareForBodyFormat(HttpRequest request, String method) {
        HttpRequest preparedRequest = request.withMethod(method);
        if (request.query() == null || request.query().isEmpty()) {
            return preparedRequest;
        }
        return preparedRequest.withPath(request.pathWithoutQuery());
    }

    public static HttpRequest applyBodyFormat(HttpRequest request, Map<String, String> params, RequestBodyFormat format) {
        return switch (format) {
            case URL_ENCODED -> request
                .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(renderUrlEncoded(params));
            case JSON -> request
                .withUpdatedHeader("Content-Type", "application/json")
                .withBody(renderJson(params));
            case XML -> request
                .withUpdatedHeader("Content-Type", "application/xml")
                .withBody(renderXml(params));
            case MULTIPART -> {
                String boundary = "----WebKitFormBoundary"
                    + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
                yield request
                    .withUpdatedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .withBody(renderMultipart(params, boundary));
            }
        };
    }

    public static HttpRequest replaceParameterName(HttpRequest request, LocatedParameter parameter, String newName) {
        if (parameter.location() == ParameterLocation.QUERY) {
            return request.withPath(QueryStringUtils.replaceName(request.path(), parameter.name(), newName));
        }

        String contentType = request.headerValue("Content-Type");
        if (contentType == null) {
            return request;
        }

        String body = request.bodyToString();
        String newBody = body;
        if (contentType.contains("application/x-www-form-urlencoded")) {
            newBody = replaceFormParameterName(body, parameter.name(), newName);
        } else if (contentType.contains("application/json")) {
            newBody = body.replaceAll(
                "\"" + Pattern.quote(parameter.name()) + "\"\\s*:",
                "\"" + Matcher.quoteReplacement(newName) + "\":"
            );
        } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            newBody = body.replaceAll(
                "<" + Pattern.quote(parameter.name()) + ">",
                "<" + Matcher.quoteReplacement(newName) + ">"
            ).replaceAll(
                "</" + Pattern.quote(parameter.name()) + ">",
                "</" + Matcher.quoteReplacement(newName) + ">"
            );
        } else if (contentType.contains("multipart/form-data")) {
            newBody = body.replaceAll(
                "name=\"" + Pattern.quote(parameter.name()) + "\"",
                "name=\"" + Matcher.quoteReplacement(newName) + "\""
            );
        }

        return request.withBody(newBody);
    }

    public static HttpRequest replaceParameterValue(HttpRequest request, LocatedParameter parameter, String newValue) {
        if (parameter.location() == ParameterLocation.QUERY) {
            return request.withPath(QueryStringUtils.replaceValue(request.path(), parameter.name(), newValue));
        }

        String contentType = request.headerValue("Content-Type");
        if (contentType == null) {
            return request;
        }

        String body = request.bodyToString();
        String newBody = body;
        if (contentType.contains("application/x-www-form-urlencoded")) {
            newBody = replaceFormParameterValue(body, parameter.name(), newValue);
        } else if (contentType.contains("application/json")) {
            newBody = body.replaceAll(
                "(\"" + Pattern.quote(parameter.name()) + "\"\\s*:\\s*)\"[^\"]*\"",
                "$1\"" + Matcher.quoteReplacement(newValue) + "\""
            );
            newBody = newBody.replaceAll(
                "(\"" + Pattern.quote(parameter.name()) + "\"\\s*:\\s*)[^,}\\]]+",
                "$1\"" + Matcher.quoteReplacement(newValue) + "\""
            );
        } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            String pattern = "(<" + Pattern.quote(parameter.name()) + ">)[^<]*(</" + Pattern.quote(parameter.name()) + ">)";
            newBody = body.replaceAll(pattern, "$1" + Matcher.quoteReplacement(newValue) + "$2");
        } else if (contentType.contains("multipart/form-data")) {
            newBody = body.replaceAll(
                "(name=\"" + Pattern.quote(parameter.name()) + "\"\\r\\n\\r\\n)[^\\r\\n]*",
                "$1" + Matcher.quoteReplacement(newValue)
            );
        }

        return request.withBody(newBody);
    }

    public static HttpRequest moveQueryToBody(HttpRequest request, String method) {
        String query = request.query();
        if (query == null || query.isEmpty()) {
            return request.withMethod(method);
        }

        return request
            .withMethod(method)
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBody(query)
            .withPath(request.pathWithoutQuery());
    }

    public static HttpRequest moveBodyToQuery(HttpRequest request, String method, String bodyParams) {
        return request
            .withMethod(method)
            .withPath(RequestPathUtils.replaceQuery(request.path(), bodyParams))
            .withBody("");
    }

    public static HttpRequest putParamsInBoth(HttpRequest request, String method, String params) {
        return request
            .withMethod(method)
            .withPath(RequestPathUtils.replaceQuery(request.pathWithoutQuery(), params))
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBody(params);
    }

    public static Map<String, String> parseBodyParameters(String body, String contentType) {
        if (body == null || body.isEmpty() || contentType == null) {
            return new LinkedHashMap<>();
        }

        if (contentType.contains("application/x-www-form-urlencoded")) {
            return parseUrlEncoded(body);
        }
        if (contentType.contains("application/json")) {
            return parseJson(body);
        }
        if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            return parseXml(body);
        }
        if (contentType.contains("multipart/form-data")) {
            return parseMultipart(body, contentType);
        }
        return new LinkedHashMap<>();
    }

    public static String renderUrlEncoded(Map<String, String> params) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (body.length() > 0) {
                body.append("&");
            }
            body.append(urlEncode(entry.getKey())).append("=").append(urlEncode(entry.getValue()));
        }
        return body.toString();
    }

    public static String renderJson(Map<String, String> params) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                json.append(",");
            }
            json.append("\"").append(escapeJson(entry.getKey())).append("\":")
                .append("\"").append(escapeJson(entry.getValue())).append("\"");
            first = false;
        }
        json.append("}");
        return json.toString();
    }

    public static String renderXml(Map<String, String> params) {
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n");
        for (Map.Entry<String, String> entry : params.entrySet()) {
            xml.append("  <").append(escapeXml(entry.getKey())).append(">")
                .append(escapeXml(entry.getValue()))
                .append("</").append(escapeXml(entry.getKey())).append(">\n");
        }
        xml.append("</root>");
        return xml.toString();
    }

    public static String renderMultipart(Map<String, String> params, String boundary) {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            body.append("--").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"").append(entry.getKey()).append("\"\r\n\r\n");
            body.append(entry.getValue()).append("\r\n");
        }
        body.append("--").append(boundary).append("--\r\n");
        return body.toString();
    }

    private static Map<String, String> parseUrlEncoded(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = decode(pair.substring(0, idx));
                String value = idx < pair.length() - 1 ? decode(pair.substring(idx + 1)) : "";
                params.put(key, value);
            } else if (!pair.isEmpty()) {
                params.put(decode(pair), "");
            }
        }
        return params;
    }

    private static Map<String, String> parseJson(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            String json = body.trim();
            if (!json.startsWith("{") || !json.endsWith("}")) {
                return params;
            }

            json = json.substring(1, json.length() - 1);
            String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    String key = kv[0].trim().replaceAll("^\"|\"$", "");
                    String value = kv[1].trim().replaceAll("^\"|\"$", "");
                    params.put(key, value);
                }
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static Map<String, String> parseXml(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            Pattern pattern = Pattern.compile(
                "<([a-zA-Z][a-zA-Z0-9_:-]*)>([^<]+)</\\1>",
                Pattern.DOTALL
            );
            Matcher matcher = pattern.matcher(body.trim());
            while (matcher.find()) {
                String tagName = matcher.group(1);
                String value = matcher.group(2).trim();
                if (!value.isEmpty()) {
                    params.put(tagName, value);
                }
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static Map<String, String> parseMultipart(String body, String contentType) {
        Map<String, String> params = new LinkedHashMap<>();
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return params;
        }

        try {
            String[] parts = body.split("--" + Pattern.quote(boundary));
            for (String part : parts) {
                if (!part.contains("Content-Disposition: form-data")) {
                    continue;
                }

                int nameStart = part.indexOf("name=\"");
                if (nameStart == -1) {
                    continue;
                }
                nameStart += 6;
                int nameEnd = part.indexOf("\"", nameStart);
                if (nameEnd == -1) {
                    continue;
                }

                int valueStart = part.indexOf("\r\n\r\n");
                if (valueStart == -1) {
                    continue;
                }

                String name = part.substring(nameStart, nameEnd);
                String value = part.substring(valueStart + 4).trim();
                params.put(name, value);
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static String replaceFormParameterName(String body, String oldName, String newName) {
        Map<String, String> params = parseUrlEncoded(body);
        if (!params.containsKey(oldName)) {
            return body;
        }

        Map<String, String> renamed = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String name = entry.getKey().equals(oldName) ? newName : entry.getKey();
            renamed.put(name, entry.getValue());
        }
        return renderUrlEncoded(renamed);
    }

    private static String replaceFormParameterValue(String body, String name, String newValue) {
        Map<String, String> params = parseUrlEncoded(body);
        if (!params.containsKey(name)) {
            return body;
        }
        params.put(name, newValue);
        return renderUrlEncoded(params);
    }

    private static String extractBoundary(String contentType) {
        if (contentType == null || !contentType.contains("boundary=")) {
            return null;
        }

        int boundaryStart = contentType.indexOf("boundary=") + 9;
        String boundary = contentType.substring(boundaryStart).trim();
        int delimiter = boundary.indexOf(';');
        return delimiter == -1 ? boundary : boundary.substring(0, delimiter);
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private static String escapeXml(String value) {
        return value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;");
    }
}
