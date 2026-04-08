package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

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

        List<String> parameterNames = parameterNames(context);
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : parameterNames) {
            variants.add(variant(
                targetRequest,
                QueryStringUtils.upsertDecodedParameter(targetRequest.path(), parameterName, authorized),
                parameterName + "=" + authorized
            ));
        }
        if (parameterNames.size() >= 2) {
            String first = parameterNames.get(0);
            String second = parameterNames.get(1);
            variants.add(variant(
                targetRequest,
                QueryStringUtils.upsertDecodedParameter(
                    QueryStringUtils.upsertDecodedParameter(targetRequest.path(), first, authorized),
                    second,
                    target
                ),
                first + "=" + authorized + " & " + second + "=" + target
            ));
        }
        return variants;
    }

    private static List<String> parameterNames(IdorRequestContext context) {
        if (context.hasQueryIdentifier()) {
            return context.queryParameterNamesOrDefaults("accountId", "id");
        }
        return context.discoveredParameterNamesOrDefaults("accountId", "id");
    }

    private static IdorRequestVariant variant(HttpRequest request, String updatedPath, String label) {
        return new IdorRequestVariant(label + " -> " + RequestPathUtils.pathWithoutQuery(updatedPath), request.withPath(updatedPath));
    }
}
