package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.identifier_aliases
 * Try common alternate parameter names that applications may use to resolve an object identifier.
 */
public class IdentifierAliasesPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of(
        "id",
        "userId",
        "accountId",
        "profileId",
        "objectId",
        "resourceId",
        "username",
        "email",
        "phone"
    );

    @Override
    public String id() {
        return "idor.query.identifier_aliases";
    }

    @Override
    public String displayName() {
        return "Identifier Aliases";
    }

    @Override
    public String description() {
        return "Try common alternate identifier parameter names such as id, userId, accountId, username, and email.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String target = context.targetIdentifier();
        if (target.isEmpty()) {
            return List.of();
        }

        // Skip parameter names already in the target request — those are
        // identical to the baseline. Only emit ALIAS names the app might
        // also accept (userId, accountId, etc.).
        java.util.Set<String> existing = new java.util.HashSet<>(context.discoveredParameterNamesOrDefaults());
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : QueryPlaybookSupport.mergedParameterNames(context, PARAMETER_NAMES)) {
            if (existing.contains(parameterName)) {
                // Array-notation: REPLACE the original param with the bracket
                // form so the request has id[]=carlos instead of id=carlos&id[]=carlos.
                // Tests if the app accepts the array form as the primary identifier.
                String stripped = com.bypassfuzzer.burp.http.QueryStringUtils.removeParameter(
                    targetRequest.path(), parameterName);
                for (String bracketName : List.of(parameterName + "[]", parameterName + "[0]")) {
                    String withBracket = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                        stripped, bracketName, target);
                    variants.add(new IdorRequestVariant(
                        bracketName + "=" + target,
                        targetRequest.withPath(withBracket)
                    ));
                }
                continue;
            }
            QueryPlaybookSupport.addUpsertVariant(
                variants,
                targetRequest,
                parameterName,
                target,
                parameterName + "=" + target
            );
        }
        return variants;
    }
}
