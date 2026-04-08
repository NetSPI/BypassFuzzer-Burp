package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.comma_separated_identifiers
 * Try comma-separated identifier lists in likely query parameters.
 */
public class CommaSeparatedIdentifiersPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of("id", "ids", "user_id", "userIds", "accountId");

    @Override
    public String id() {
        return "idor.query.comma_separated_identifiers";
    }

    @Override
    public String displayName() {
        return "Comma-Separated Identifiers";
    }

    @Override
    public String description() {
        return "Try comma-separated identifier lists such as target,authorized and authorized,target in query parameters.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : QueryPlaybookSupport.parameterNames(context, PARAMETER_NAMES)) {
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                target + "," + authorized,
                parameterName + "=" + target + "," + authorized
            );
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                authorized + "," + target,
                parameterName + "=" + authorized + "," + target
            );
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                target + "," + authorized + "," + target,
                parameterName + "=" + target + "," + authorized + "," + target
            );
        }
        return variants;
    }
}
