package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.json_batch_identifiers
 * Turn a discovered JSON identifier into an array or batch-style list.
 */
public class JsonBatchIdentifiersPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.json_batch_identifiers";
    }

    @Override
    public String displayName() {
        return "JSON Batch Identifiers";
    }

    @Override
    public String description() {
        return "Try JSON array-wrapped and mixed authorized/target identifier batches in discovered JSON fields.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "[" + IdorPlaybookSupport.toJsonScalar(target) + "]",
                "target array"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "[" + IdorPlaybookSupport.toJsonScalar(authorized) + "," + IdorPlaybookSupport.toJsonScalar(target) + "]",
                "authorized,target batch"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "[" + IdorPlaybookSupport.toJsonScalar(target) + "," + IdorPlaybookSupport.toJsonScalar(authorized) + "]",
                "target,authorized batch"
            );

            // Bracket-notation keys: PHP/Express body-parsers interpret
            // "id[]" and "id[0]" as array accessors even in JSON bodies.
            String name = parameter.name();
            String tScalar = IdorPlaybookSupport.toJsonScalar(target);
            String aScalar = IdorPlaybookSupport.toJsonScalar(authorized);
            addBracketKeyVariant(variants, targetRequest, name, name + "[]", tScalar, "id[]");
            addBracketKeyVariant(variants, targetRequest, name, name + "[0]", tScalar, "id[0]");
            addBracketKeyVariant(variants, targetRequest, name, name + "[1]", tScalar, "id[1]");
            // Mixed: id[0]=authorized, id[1]=target
            String mixedReplacement = java.util.regex.Matcher.quoteReplacement(
                "\"" + name + "[0]\":" + aScalar + ",\"" + name + "[1]\":" + tScalar);
            String mixedBody = targetRequest.bodyToString()
                .replaceFirst(
                    "\"" + java.util.regex.Pattern.quote(name) + "\"\\s*:\\s*" + java.util.regex.Pattern.quote(tScalar),
                    mixedReplacement
                );
            if (!mixedBody.equals(targetRequest.bodyToString())) {
                variants.add(new IdorRequestVariant(
                    "id[0]=auth,id[1]=target",
                    targetRequest.withBody(mixedBody)
                ));
            }
        }
        return variants;
    }

    private static void addBracketKeyVariant(List<IdorRequestVariant> variants,
                                              HttpRequest request,
                                              String originalKey,
                                              String bracketKey,
                                              String valueScalar,
                                              String label) {
        String body = request.bodyToString();
        String updated = body.replaceFirst(
            "\"" + java.util.regex.Pattern.quote(originalKey) + "\"",
            "\"" + bracketKey + "\""
        );
        if (!updated.equals(body)) {
            variants.add(new IdorRequestVariant(label, request.withBody(updated)));
        }
    }
}
