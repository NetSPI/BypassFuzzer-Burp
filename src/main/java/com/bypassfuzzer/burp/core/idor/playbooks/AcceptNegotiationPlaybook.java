package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.accept_negotiation
 * Change response content negotiation to catch representation-specific authorization gaps.
 */
public class AcceptNegotiationPlaybook implements IdorPlaybook {

    private static final List<String> ACCEPTS = List.of(
        "application/json",
        "application/xml",
        "text/html",
        "*/*"
    );

    @Override
    public String id() {
        return "idor.hybrid.accept_negotiation";
    }

    @Override
    public String displayName() {
        return "Accept Negotiation";
    }

    @Override
    public String description() {
        return "Change the Accept header to probe representation-specific object access and serialization paths.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String accept : ACCEPTS) {
            variants.add(new IdorRequestVariant(
                "Accept=" + accept,
                targetRequest.withUpdatedHeader("Accept", accept)
            ));
        }
        return variants;
    }
}
