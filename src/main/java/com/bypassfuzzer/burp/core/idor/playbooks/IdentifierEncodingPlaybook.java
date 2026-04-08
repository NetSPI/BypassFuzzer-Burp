package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PLAYBOOK: idor.hybrid.identifier_encoding
 * Borrow targeted encoding ideas from the bypass tab, but only for the identifier literal.
 */
public class IdentifierEncodingPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.identifier_encoding";
    }

    @Override
    public String displayName() {
        return "Identifier Encoding";
    }

    @Override
    public String description() {
        return "Apply targeted URL and double-URL encodings to the identifier segment only.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String targetIdentifier = context.targetIdentifier();
        if (targetIdentifier.isEmpty()) {
            return List.of();
        }

        List<String> candidates = encodedCandidates(targetIdentifier);
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
            candidate -> "path encoding " + candidate
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
                    parameter.location().name().toLowerCase() + " encoding " + parameter.path() + " -> " + candidate,
                    updated
                ));
            }
        }
        return variants;
    }

    private static List<String> encodedCandidates(String value) {
        Set<String> candidates = new LinkedHashSet<>();
        addCandidate(candidates, value, encodeUrl(value));
        addCandidate(candidates, value, encodeDoubleUrl(value));
        addCandidate(candidates, value, partialEncodeLeadingChar(value));
        addCandidate(candidates, value, partialEncodeMiddleChar(value));
        addCandidate(candidates, value, encodeUrl("{" + value + "}"));
        addCandidate(candidates, value, Base64.getEncoder().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return new ArrayList<>(candidates);
    }

    private static void addCandidate(Set<String> candidates, String original, String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.equals(original)) {
            return;
        }
        candidates.add(candidate);
    }

    private static String encodeUrl(String value) {
        StringBuilder encoded = new StringBuilder();
        for (char c : value.toCharArray()) {
            encoded.append(String.format("%%%02X", (int) c));
        }
        return encoded.toString();
    }

    private static String encodeDoubleUrl(String value) {
        StringBuilder encoded = new StringBuilder();
        for (char c : value.toCharArray()) {
            encoded.append(String.format("%%25%02X", (int) c));
        }
        return encoded.toString();
    }

    private static String partialEncodeLeadingChar(String value) {
        if (value.isEmpty()) {
            return value;
        }
        char leading = value.charAt(0);
        return String.format("%%%02X", (int) leading) + value.substring(1);
    }

    private static String partialEncodeMiddleChar(String value) {
        if (value.length() < 2) {
            return value;
        }
        int middle = value.length() / 2;
        return value.substring(0, middle)
            + String.format("%%%02X", (int) value.charAt(middle))
            + value.substring(middle + 1);
    }
}
