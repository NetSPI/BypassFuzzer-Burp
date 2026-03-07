package com.bypassfuzzer.burp.http;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Query-string parsing and rewriting helpers that preserve parameter order.
 */
public final class QueryStringUtils {

    private QueryStringUtils() {
    }

    public static Map<String, String> parseRaw(String query) {
        return parse(query, false);
    }

    public static Map<String, String> parseDecoded(String query) {
        return parse(query, true);
    }

    public static Map<String, String> parsePathQueryDecoded(String pathWithQuery) {
        return parseDecoded(RequestPathUtils.queryFromPath(pathWithQuery));
    }

    private static Map<String, String> parse(String query, boolean decodeValues) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            if (pair.isEmpty()) {
                continue;
            }

            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String name = pair.substring(0, eqIdx);
                String value = eqIdx < pair.length() - 1 ? pair.substring(eqIdx + 1) : "";
                params.put(name, decodeValues ? decode(value) : value);
            } else {
                params.put(pair, "");
            }
        }

        return params;
    }

    public static String toQueryString(Map<String, String> params) {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (query.length() > 0) {
                query.append("&");
            }
            query.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return query.toString();
    }

    public static String replaceValue(String pathWithQuery, String parameterName, String value) {
        Map<String, String> params = parseRaw(RequestPathUtils.queryFromPath(pathWithQuery));
        if (!params.containsKey(parameterName)) {
            return pathWithQuery;
        }

        params.put(parameterName, value);
        return RequestPathUtils.replaceQuery(pathWithQuery, toQueryString(params));
    }

    public static String replaceName(String pathWithQuery, String oldName, String newName) {
        Map<String, String> params = parseRaw(RequestPathUtils.queryFromPath(pathWithQuery));
        if (!params.containsKey(oldName)) {
            return pathWithQuery;
        }

        Map<String, String> renamed = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String name = entry.getKey().equals(oldName) ? newName : entry.getKey();
            renamed.put(name, entry.getValue());
        }

        return RequestPathUtils.replaceQuery(pathWithQuery, toQueryString(renamed));
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
