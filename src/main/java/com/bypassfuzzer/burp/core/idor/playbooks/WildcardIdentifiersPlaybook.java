package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.wildcard_identifiers
 * Swap JSON identifier fields to wildcard-like values that sometimes trigger broad object lookups.
 */
public class WildcardIdentifiersPlaybook implements IdorPlaybook {

    private static final List<String> PAYLOADS = List.of("*", "%", "_", ".");

    @Override
    public String id() {
        return "idor.body.wildcard_identifiers";
    }

    @Override
    public String displayName() {
        return "Wildcard Identifiers";
    }

    @Override
    public String description() {
        return "Try wildcard-like identifier values such as *, %, _, and . inside discovered JSON fields.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        IdorPlaybookSupport.addBodyIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            PAYLOADS,
            true,
            label -> "wildcard " + label
        );
        return variants;
    }
}
