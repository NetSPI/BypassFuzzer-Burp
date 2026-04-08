package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.unexpected_data_types
 * Change JSON identifier fields into booleans, nulls, arrays, numbers, and operator-like objects.
 */
public class UnexpectedDataTypesPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.unexpected_data_types";
    }

    @Override
    public String displayName() {
        return "Unexpected Data Types";
    }

    @Override
    public String description() {
        return "Try booleans, nulls, numbers, arrays, and operator-like objects in discovered JSON identifier fields.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        String target = context.targetIdentifier();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter, "true", "boolean=true");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter, "null", "null");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter, "1", "number=1");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter, "[true]", "array=[true]");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "[" + IdorPlaybookSupport.toJsonScalar(target) + ",true]",
                "array=[target,true]"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "{\"$ne\":" + IdorPlaybookSupport.toJsonScalar(target) + "}",
                "object={$ne:target}"
            );
        }
        return variants;
    }

}
