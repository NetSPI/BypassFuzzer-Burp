package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.RawRequestMutationSupport;

/**
 * Rewrites exact identifier literals across a raw request for IDOR/BOLA testing.
 */
public class IdorRequestMutator {

    private final RawRequestMutationSupport.RequestRebuilder requestRebuilder;

    public IdorRequestMutator() {
        this(HttpRequest::httpRequest);
    }

    public IdorRequestMutator(RawRequestMutationSupport.RequestRebuilder requestRebuilder) {
        this.requestRebuilder = requestRebuilder;
    }

    public int countOccurrences(HttpRequest request, String identifier) {
        return RawRequestMutationSupport.countOccurrences(request, identifier);
    }

    public HttpRequest replaceIdentifier(HttpRequest request, String sourceIdentifier, String targetIdentifier) {
        return RawRequestMutationSupport.replaceAll(request, sourceIdentifier, targetIdentifier, requestRebuilder);
    }
}
