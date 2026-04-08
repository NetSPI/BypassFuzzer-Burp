package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.uuid_neighbor_edits
 * Try small sequential and pattern-preserving edits against UUID-like and hex-like identifiers.
 */
public class UuidNeighborEditsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.uuid_neighbor_edits";
    }

    @Override
    public String displayName() {
        return "UUID Neighbor Edits";
    }

    @Override
    public String description() {
        return "Try small last-byte, last-nibble, and last-quartet edits against UUID-like or hex-like identifiers.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        List<String> candidates = IdorIdentifierShapeSupport.neighborCandidates(context.targetIdentifier());
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
            candidate -> "path neighbor " + candidate
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
                    parameter.location().name().toLowerCase() + " neighbor " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }
}
