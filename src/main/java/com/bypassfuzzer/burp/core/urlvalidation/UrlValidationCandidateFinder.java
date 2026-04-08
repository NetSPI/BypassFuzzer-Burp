package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.RawRequestMutationSupport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Builds marker-based mutators for URL validation requests.
 */
public class UrlValidationCandidateFinder {
    private final RawRequestMutationSupport.RequestRebuilder requestRebuilder;

    public UrlValidationCandidateFinder() {
        this(HttpRequest::httpRequest);
    }

    public UrlValidationCandidateFinder(RawRequestMutationSupport.RequestRebuilder requestRebuilder) {
        this.requestRebuilder = requestRebuilder;
    }

    public List<UrlValidationCandidate> find(HttpRequest request, UrlValidationOptions options) {
        return findMarkerCandidates(request, options);
    }

    public int countMarkerOccurrences(HttpRequest request, String markerText) {
        String marker = markerText == null ? "" : markerText.trim();
        return RawRequestMutationSupport.countOccurrences(request, marker);
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
        return RawRequestMutationSupport.replaceAll(request, marker, newValue, requestRebuilder);
    }
}
