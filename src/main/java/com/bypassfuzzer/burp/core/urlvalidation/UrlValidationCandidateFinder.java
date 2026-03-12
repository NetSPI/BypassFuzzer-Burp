package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Builds marker-based mutators for URL validation requests.
 */
public class UrlValidationCandidateFinder {
    private final RequestRebuilder requestRebuilder;

    public UrlValidationCandidateFinder() {
        this(HttpRequest::httpRequest);
    }

    public UrlValidationCandidateFinder(RequestRebuilder requestRebuilder) {
        this.requestRebuilder = requestRebuilder;
    }

    public List<UrlValidationCandidate> find(HttpRequest request, UrlValidationOptions options) {
        return findMarkerCandidates(request, options);
    }

    public int countMarkerOccurrences(HttpRequest request, String markerText) {
        if (request == null) {
            return 0;
        }

        String marker = markerText == null ? "" : markerText.trim();
        if (marker.isEmpty()) {
            return 0;
        }

        String rawRequest = request.toString();
        int count = 0;
        int index = 0;
        while ((index = rawRequest.indexOf(marker, index)) >= 0) {
            count++;
            index += marker.length();
        }
        return count;
    }

    private List<UrlValidationCandidate> findMarkerCandidates(HttpRequest request, UrlValidationOptions options) {
        String marker = options.normalizedMarkerText();
        String rawRequest = request.toString();
        if (countOccurrences(rawRequest, marker) == 0) {
            return Collections.emptyList();
        }

        List<UrlValidationCandidate> candidates = new ArrayList<>(1);
        candidates.add(new UrlValidationCandidate(
            marker,
            marker,
            "marker",
            (baseRequest, newValue) -> replaceMarkers(baseRequest, marker, newValue)
        ));
        return candidates;
    }

    private int countOccurrences(String text, String marker) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(marker, index)) >= 0) {
            count++;
            index += marker.length();
        }
        return count;
    }

    private HttpRequest replaceMarkers(HttpRequest request, String marker, String newValue) {
        String mutatedRequest = request.toString().replace(marker, newValue);
        return requestRebuilder.rebuild(request.httpService(), syncContentLength(mutatedRequest));
    }

    private String syncContentLength(String rawRequest) {
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

    private boolean hasTransferEncoding(String[] headerLines) {
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
