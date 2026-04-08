package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.path.special_identifier_values
 * Swap the target identifier for sentinel values from common IDOR notes.
 */
public class SpecialIdentifierValuesPlaybook implements IdorPlaybook {

    private static final List<String> CANDIDATES = List.of("0", "1", "-1", "%C3%87");

    @Override
    public String id() {
        return "idor.path.special_identifier_values";
    }

    @Override
    public String displayName() {
        return "Special Identifier Values";
    }

    @Override
    public String description() {
        return "Try sentinel identifier values like 0, -1, and encoded non-ASCII characters in discovered path and body identifier locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        if (context.targetIdentifier().isEmpty()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        IdorPlaybookSupport.addPathIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            CANDIDATES,
            candidate -> candidate
        );
        IdorPlaybookSupport.addBodyIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            CANDIDATES,
            false,
            label -> "body " + label
        );
        return variants;
    }
}
