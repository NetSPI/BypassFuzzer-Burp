package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.uuid_version_variants
 * Try UUID version swaps such as v1/v3/v4/v5 while keeping the rest of the identifier shape stable.
 */
public class UuidVersionVariantsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.uuid_version_variants";
    }

    @Override
    public String displayName() {
        return "UUID Version Variants";
    }

    @Override
    public String description() {
        return "Try v1, v3, v4, and v5-style UUID versions in the same discovered identifier location.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        List<String> candidates = IdorIdentifierShapeSupport.uuidVersionCandidates(context.targetIdentifier());
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
            candidate -> "path uuid-version " + candidate
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
                    parameter.location().name().toLowerCase() + " uuid-version " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }
}
