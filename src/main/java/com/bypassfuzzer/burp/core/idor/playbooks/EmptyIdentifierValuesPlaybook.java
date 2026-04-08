package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.empty_identifier_values
 * Try empty, blank-ish, nullish, and undefined identifier values in discovered identifier locations.
 */
public class EmptyIdentifierValuesPlaybook implements IdorPlaybook {

    private static final List<String> GENERAL_CANDIDATES = List.of("", "null", "undefined");
    private static final String PATH_QUERY_WHITESPACE = "%20";
    private static final String BODY_WHITESPACE = " ";

    @Override
    public String id() {
        return "idor.hybrid.empty_identifier_values";
    }

    @Override
    public String displayName() {
        return "Empty Identifier Values";
    }

    @Override
    public String description() {
        return "Try empty strings, whitespace-only values, null, and undefined in discovered identifier locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String targetIdentifier = context.targetIdentifier();
        if (targetIdentifier.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();

        IdorPlaybookSupport.addPathIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            pathCandidates(),
            candidate -> "path " + (candidate.isEmpty() ? "<empty>" : candidate)
        );

        for (LocatedParameter parameter : context.identifierParameters()) {
            if (parameter.location() != ParameterLocation.QUERY && !parameter.isBody()) {
                continue;
            }
            for (String candidate : valueCandidates(parameter)) {
                HttpRequest updated = replace(targetRequest, parameter, candidate);
                String before = parameter.isBody() ? targetRequest.bodyToString() : targetRequest.path();
                String after = parameter.isBody() ? updated.bodyToString() : updated.path();
                if (before.equals(after)) {
                    continue;
                }
                variants.add(new IdorRequestVariant(
                    parameter.location().name().toLowerCase() + " " + parameter.path() + " -> " + display(candidate),
                    updated
                ));
            }
        }
        return variants;
    }

    private static List<String> pathCandidates() {
        List<String> candidates = new ArrayList<>(GENERAL_CANDIDATES);
        candidates.add(PATH_QUERY_WHITESPACE);
        return candidates;
    }

    private static List<String> valueCandidates(LocatedParameter parameter) {
        List<String> candidates = new ArrayList<>(GENERAL_CANDIDATES);
        candidates.add(parameter.isBody() ? BODY_WHITESPACE : PATH_QUERY_WHITESPACE);
        return candidates;
    }

    private static HttpRequest replace(HttpRequest request, LocatedParameter parameter, String candidate) {
        if (parameter.isBody()
            && "null".equals(candidate)
            && request.headerValue("Content-Type") != null
            && request.headerValue("Content-Type").toLowerCase().contains("application/json")) {
            return RequestParameterSupport.replaceJsonParameterValueWithJson(request, parameter, "null");
        }
        return RequestParameterSupport.replaceParameterValue(request, parameter, candidate);
    }

    private static String display(String candidate) {
        if (candidate.isEmpty()) {
            return "<empty>";
        }
        if (" ".equals(candidate)) {
            return "<space>";
        }
        return candidate;
    }
}
