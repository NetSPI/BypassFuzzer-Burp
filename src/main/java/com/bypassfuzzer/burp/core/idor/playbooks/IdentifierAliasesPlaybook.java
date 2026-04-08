package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

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

        List<IdorRequestVariant> variants = new ArrayList<>();
        java.util.LinkedHashSet<String> parameterNames = new java.util.LinkedHashSet<>(context.discoveredParameterNamesOrDefaults());
        parameterNames.addAll(PARAMETER_NAMES);
        for (String parameterName : parameterNames) {
            String updatedPath = QueryStringUtils.upsertDecodedParameter(targetRequest.path(), parameterName, target);
            variants.add(new IdorRequestVariant(
                parameterName + "=" + target + " -> " + RequestPathUtils.pathWithoutQuery(updatedPath),
                targetRequest.withPath(updatedPath)
            ));
        }
        return variants;
    }
}
