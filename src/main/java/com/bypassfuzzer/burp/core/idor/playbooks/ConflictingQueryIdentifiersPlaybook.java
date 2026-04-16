package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.conflicting_identifiers
 * Add conflicting identifier hints in query parameters to probe parser precedence.
 */
public class ConflictingQueryIdentifiersPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.query.conflicting_identifiers";
    }

    @Override
    public String displayName() {
        return "Conflicting Query Identifiers";
    }

    @Override
    public String description() {
        return "Layer path identifier 2 with query parameters that reference identifier 1 or duplicate identifier 2.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        // Cross-source conflict: one source (path or body) carries the target,
        // query carries the authorized. If the identifier is query-only, there's
        // no cross-source disagreement to test.
        if (!context.hasPathIdentifier() && !context.hasBodyIdentifier()) {
            return List.of();
        }

        List<String> parameterNames = QueryPlaybookSupport.parameterNames(context, List.of("accountId", "id"));
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : parameterNames) {
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                authorized,
                parameterName + "=" + authorized
            );
        }
        if (parameterNames.size() >= 2) {
            String first = parameterNames.get(0);
            String second = parameterNames.get(1);
            String firstUpdated = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(targetRequest.path(), first, authorized);
            String updatedPath = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(firstUpdated, second, target);
            variants.add(new IdorRequestVariant(
                first + "=" + authorized + " & " + second + "=" + target
                    + " -> " + com.bypassfuzzer.burp.http.RequestPathUtils.pathWithoutQuery(updatedPath),
                targetRequest.withPath(updatedPath)
            ));
        }
        return variants;
    }
}
