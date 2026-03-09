package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;

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
        return requestRebuilder.rebuild(request.httpService(), request.toString().replace(marker, newValue));
    }

    @FunctionalInterface
    public interface RequestRebuilder {
        HttpRequest rebuild(HttpService service, String rawRequest);
    }
}
