package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.canonical_identifier_formats
 * Try canonical and non-canonical UUID forms such as compact, braced, and uppercase variants.
 */
public class CanonicalIdentifierFormatsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.canonical_identifier_formats";
    }

    @Override
    public String displayName() {
        return "Canonical Identifier Formats";
    }

    @Override
    public String description() {
        return "Try compact, braced, and uppercase/lowercase UUID-like identifier formats in discovered locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        List<String> candidates = IdorIdentifierShapeSupport.canonicalUuidCandidates(context.targetIdentifier());
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
            candidate -> "path canonical " + candidate
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
                    parameter.location().name().toLowerCase() + " canonical " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }
}
