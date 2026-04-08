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
        }
        return variants;
    }
}
