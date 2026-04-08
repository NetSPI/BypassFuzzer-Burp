package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.parameter_pollution
 * Append duplicate identifier parameters in different orders to catch first-wins and last-wins behavior.
 */
public class ParameterPollutionPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of("id", "accountId");

    @Override
    public String id() {
        return "idor.query.parameter_pollution";
    }

    @Override
    public String displayName() {
        return "Parameter Pollution";
    }

    @Override
    public String description() {
        return "Try duplicate identifier parameters such as id=target&id=authorized in different orders.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : parameterNames(context)) {
            addVariant(variants, targetRequest, parameterName, target, target);
            addVariant(variants, targetRequest, parameterName, authorized, target);
            addVariant(variants, targetRequest, parameterName, target, authorized);
        }
        return variants;
    }

    private static List<String> parameterNames(IdorRequestContext context) {
        if (context.hasQueryIdentifier()) {
            return context.queryParameterNamesOrDefaults(PARAMETER_NAMES.toArray(String[]::new));
        }
        return context.discoveredParameterNamesOrDefaults(PARAMETER_NAMES.toArray(String[]::new));
    }

    private static void addVariant(List<IdorRequestVariant> variants,
                                   HttpRequest request,
                                   String parameterName,
                                   String firstValue,
                                   String secondValue) {
        String updatedPath = QueryStringUtils.appendDecodedParameter(request.path(), parameterName, firstValue);
        updatedPath = QueryStringUtils.appendDecodedParameter(updatedPath, parameterName, secondValue);
        variants.add(new IdorRequestVariant(
            parameterName + "=" + firstValue + " & " + parameterName + "=" + secondValue
                + " -> " + RequestPathUtils.pathWithoutQuery(updatedPath),
            request.withPath(updatedPath)
        ));
    }
}
