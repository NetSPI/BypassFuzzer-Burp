package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.truncated_identifier_variants
 * Try shortened, zero-padded, and all-zero identifier forms against UUID-like and hex-like values.
 */
public class TruncatedIdentifierVariantsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.truncated_identifier_variants";
    }

    @Override
    public String displayName() {
        return "Truncated Identifier Variants";
    }

    @Override
    public String description() {
        return "Try first/last chunks, zero-padded forms, and all-zero UUID-like variants in discovered locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        List<String> candidates = IdorIdentifierShapeSupport.truncatedCandidates(context.targetIdentifier());
        if (candidates.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        IdorPlaybookSupport.addPathIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            candidates,
            candidate -> "path truncated " + candidate
        );

        for (LocatedParameter parameter : context.identifierParameters()) {
            if (parameter.location() != ParameterLocation.QUERY && !parameter.isBody()) {
                continue;
            }
            for (String candidate : candidates) {
                HttpRequest updated = RequestParameterSupport.replaceParameterValue(targetRequest, parameter, candidate);
                String before = parameter.isBody() ? targetRequest.bodyToString() : targetRequest.path();
                String after = parameter.isBody() ? updated.bodyToString() : updated.path();
                if (before.equals(after)) {
                    continue;
                }
                variants.add(new IdorRequestVariant(
                    parameter.location().name().toLowerCase() + " truncated " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }
}
