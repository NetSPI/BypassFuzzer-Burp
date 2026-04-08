package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.json_parameter_pollution
 * Duplicate JSON identifier keys in different orders to catch first-wins and last-wins parser behavior.
 */
public class JsonParameterPollutionPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.json_parameter_pollution";
    }

    @Override
    public String displayName() {
        return "JSON Parameter Pollution";
    }

    @Override
    public String description() {
        return "Repeat JSON identifier keys in authorized/target and target/authorized order.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            addVariant(
                variants,
                targetRequest,
                parameter,
                authorized,
                target,
                "authorized,target"
            );
            addVariant(
                variants,
                targetRequest,
                parameter,
                target,
                authorized,
                "target,authorized"
            );
        }
        return variants;
    }

    private static void addVariant(List<IdorRequestVariant> variants,
                                   HttpRequest targetRequest,
                                   LocatedParameter parameter,
                                   String firstValue,
                                   String secondValue,
                                   String orderLabel) {
        HttpRequest updated = RequestParameterSupport.replaceJsonParameterWithDuplicateKeys(
            targetRequest,
            parameter,
            IdorPlaybookSupport.toJsonScalar(firstValue),
            IdorPlaybookSupport.toJsonScalar(secondValue)
        );
        if (targetRequest.bodyToString().equals(updated.bodyToString())) {
            return;
        }
        variants.add(new IdorRequestVariant(
            parameter.path() + " duplicate keys " + orderLabel,
            updated
        ));
    }
}
