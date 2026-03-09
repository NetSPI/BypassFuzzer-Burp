package com.bypassfuzzer.burp.core.urlvalidation;

import burp.api.montoya.http.message.requests.HttpRequest;

public record UrlValidationCandidate(
    String sinkName,
    String originalValue,
    String locationLabel,
    RequestMutator mutator
) {

    public String displayName() {
        return sinkName + " (" + locationLabel + ")";
    }

    @FunctionalInterface
    public interface RequestMutator {
        HttpRequest mutate(HttpRequest request, String newValue);
    }
}
