package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared literal replacement support for raw HTTP requests that need Content-Length synchronized.
 */
public final class RawRequestMutationSupport {

    private RawRequestMutationSupport() {
    }

    public static int countOccurrences(HttpRequest request, String literal) {
        if (request == null) {
            return 0;
        }
        return countOccurrences(request.toString(), literal);
    }

    public static HttpRequest replaceAll(HttpRequest request, String literal, String replacement, RequestRebuilder requestRebuilder) {
        if (request == null || requestRebuilder == null || literal == null || literal.isEmpty()) {
            return request;
        }

        String rawRequest = request.toString();
        String mutatedRequest = rawRequest.replace(literal, replacement == null ? "" : replacement);
        if (rawRequest.equals(mutatedRequest)) {
            return request;
        }

        return requestRebuilder.rebuild(request.httpService(), syncContentLength(mutatedRequest));
    }

    static int countOccurrences(String text, String literal) {
        if (text == null || text.isEmpty() || literal == null || literal.isEmpty()) {
            return 0;
        }

        int count = 0;
        int index = 0;
        while ((index = text.indexOf(literal, index)) >= 0) {
            count++;
            index += literal.length();
        }
        return count;
    }

    static String syncContentLength(String rawRequest) {
        if (rawRequest == null || rawRequest.isEmpty()) {
            return rawRequest;
        }

        String lineSeparator = rawRequest.contains("\r\n") ? "\r\n" : "\n";
        String headerSeparator = lineSeparator + lineSeparator;
        int separatorIndex = rawRequest.indexOf(headerSeparator);
        if (separatorIndex < 0) {
            return rawRequest;
        }

        String headersSection = rawRequest.substring(0, separatorIndex);
        String body = rawRequest.substring(separatorIndex + headerSeparator.length());
        String[] headerLines = headersSection.split(java.util.regex.Pattern.quote(lineSeparator), -1);
        if (headerLines.length == 0 || hasTransferEncoding(headerLines)) {
            return rawRequest;
        }

        int bodyLength = body.getBytes(StandardCharsets.UTF_8).length;
        List<String> updatedHeaderLines = new ArrayList<>(headerLines.length + 1);
        updatedHeaderLines.add(headerLines[0]);

        boolean replacedContentLength = false;
        for (int i = 1; i < headerLines.length; i++) {
            String headerLine = headerLines[i];
            if (headerLine.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
                if (!replacedContentLength) {
                    updatedHeaderLines.add("Content-Length: " + bodyLength);
                    replacedContentLength = true;
                }
                continue;
            }
            updatedHeaderLines.add(headerLine);
        }

        if (!replacedContentLength && bodyLength > 0) {
            updatedHeaderLines.add("Content-Length: " + bodyLength);
        }

        return String.join(lineSeparator, updatedHeaderLines) + headerSeparator + body;
    }

    private static boolean hasTransferEncoding(String[] headerLines) {
        for (int i = 1; i < headerLines.length; i++) {
            if (headerLines[i].regionMatches(true, 0, "Transfer-Encoding:", 0, "Transfer-Encoding:".length())) {
                return true;
            }
        }
        return false;
    }

    @FunctionalInterface
    public interface RequestRebuilder {
        HttpRequest rebuild(HttpService service, String rawRequest);
    }
}
