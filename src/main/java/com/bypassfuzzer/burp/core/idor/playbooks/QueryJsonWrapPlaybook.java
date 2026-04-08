package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.json_wrap
 * Wrap query identifier values in small JSON objects to probe parser confusion in upstream components.
 */
public class QueryJsonWrapPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of("id", "user_id", "accountId");

    @Override
    public String id() {
        return "idor.query.json_wrap";
    }

    @Override
    public String displayName() {
        return "Query JSON Wrap";
    }

    @Override
    public String description() {
        return "Try JSON-wrapped query values such as {\"id\":target} and {\"user_id\":target}.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String target = context.targetIdentifier();
        if (target.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : QueryPlaybookSupport.parameterNames(context, PARAMETER_NAMES)) {
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                "{\"id\":" + IdorPlaybookSupport.toJsonScalar(target) + "}",
                parameterName + " id wrapper"
            );
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                "{\"" + parameterName + "\":" + IdorPlaybookSupport.toJsonScalar(target) + "}",
                parameterName + " " + parameterName + " wrapper"
            );
        }
        return variants;
    }
}
