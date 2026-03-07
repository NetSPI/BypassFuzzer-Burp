package com.bypassfuzzer.burp.http;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cookie-header parsing and rewrite helpers that preserve cookie order.
 */
public final class CookieHeaderUtils {

    private CookieHeaderUtils() {
    }

    public static Map<String, String> parse(String cookieHeader) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return cookies;
        }

        String[] pairs = cookieHeader.split(";");
        for (String pair : pairs) {
            String trimmed = pair.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            int eqIdx = trimmed.indexOf('=');
            if (eqIdx <= 0) {
                continue;
            }

            String name = trimmed.substring(0, eqIdx).trim();
            String value = eqIdx < trimmed.length() - 1 ? trimmed.substring(eqIdx + 1).trim() : "";
            cookies.put(name, value);
        }

        return cookies;
    }

    public static String toHeaderValue(Map<String, String> cookies) {
        StringBuilder header = new StringBuilder();
        for (Map.Entry<String, String> entry : cookies.entrySet()) {
            if (header.length() > 0) {
                header.append("; ");
            }
            header.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return header.toString();
    }

    public static String replaceValue(String cookieHeader, String cookieName, String value) {
        Map<String, String> cookies = parse(cookieHeader);
        if (!cookies.containsKey(cookieName)) {
            return cookieHeader;
        }

        cookies.put(cookieName, value);
        return toHeaderValue(cookies);
    }

    public static String appendCookie(String cookieHeader, String cookie) {
        if (cookie == null || cookie.isEmpty()) {
            return cookieHeader;
        }
        if (cookieHeader == null || cookieHeader.isEmpty()) {
            return cookie;
        }
        return cookieHeader + "; " + cookie;
    }
}
