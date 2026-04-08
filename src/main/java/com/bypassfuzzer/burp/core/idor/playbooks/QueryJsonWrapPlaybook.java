package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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
            Set<String> wrapperValues = new LinkedHashSet<>();
            wrapperValues.add("{\"id\":" + IdorPlaybookSupport.toJsonScalar(target) + "}");
            wrapperValues.add("{\"" + parameterName + "\":" + IdorPlaybookSupport.toJsonScalar(target) + "}");

            for (String wrapperValue : wrapperValues) {
                String wrapperKey = wrapperValue.startsWith("{\"id\":") ? "id" : parameterName;
                QueryPlaybookSupport.addUpsertVariant(
                    variants,
                    targetRequest,
                    parameterName,
                    wrapperValue,
                    parameterName + " " + wrapperKey + " wrapper"
                );
            }
        }
        return variants;
    }
}
