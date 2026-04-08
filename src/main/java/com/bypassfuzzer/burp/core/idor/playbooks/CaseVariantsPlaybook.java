package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.case_variants
 * Change identifier letter casing to probe case-sensitive routing, auth, and object lookup differences.
 */
public class CaseVariantsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.case_variants";
    }

    @Override
    public String displayName() {
        return "Case Variants";
    }

    @Override
    public String description() {
        return "Try lowercase, uppercase, and alternating-case variants of the discovered identifier.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String targetIdentifier = context.targetIdentifier();
        if (targetIdentifier.isEmpty()) {
            return List.of();
        }

        List<String> candidates = caseVariants(targetIdentifier);
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
            candidate -> "path " + candidate
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
                    parameter.location().name().toLowerCase() + " " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }

    private static List<String> caseVariants(String value) {
        LinkedHashSet<String> variants = new LinkedHashSet<>();
        variants.add(value.toLowerCase());
        variants.add(value.toUpperCase());
        variants.add(alternatingCase(value, true));
        variants.add(alternatingCase(value, false));
        variants.remove(value);
        variants.removeIf(String::isBlank);
        return new ArrayList<>(variants);
    }

    private static String alternatingCase(String value, boolean startUpper) {
        StringBuilder builder = new StringBuilder(value.length());
        boolean upper = startUpper;
        for (char c : value.toCharArray()) {
            if (Character.isLetter(c)) {
                builder.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                upper = !upper;
            } else {
                builder.append(c);
            }
        }
        return builder.toString();
    }
}
