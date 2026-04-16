package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
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
        for (String parameterName : QueryPlaybookSupport.parameterNames(context, PARAMETER_NAMES)) {
            // 2-param: target request already has param=target; append one
            // more to test first-wins vs last-wins with just 2 values.
            addSingleAppend(variants, targetRequest, parameterName, authorized);

            // 3-param: target request has param=target; append two more in
            // mixed order. Some parsers take the middle value.
            addDoubleAppend(variants, targetRequest, parameterName, authorized, target);
            addDoubleAppend(variants, targetRequest, parameterName, target, authorized);
        }
        return variants;
    }

    private static void addSingleAppend(List<IdorRequestVariant> variants,
                                       HttpRequest request,
                                       String parameterName,
                                       String appendValue) {
        String label = "+" + parameterName + "=" + appendValue;
        String updatedPath = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
            request.path(), parameterName, appendValue
        );
        variants.add(new IdorRequestVariant(
            label + " -> " + com.bypassfuzzer.burp.http.RequestPathUtils.pathWithoutQuery(updatedPath),
            request.withPath(updatedPath)
        ));
    }

    private static void addDoubleAppend(List<IdorRequestVariant> variants,
                                        HttpRequest request,
                                        String parameterName,
                                        String firstValue,
                                        String secondValue) {
        String label = parameterName + "=" + firstValue + " & " + parameterName + "=" + secondValue;
        String updatedPathRequest = request.path();
        updatedPathRequest = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(updatedPathRequest, parameterName, firstValue);
        updatedPathRequest = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(updatedPathRequest, parameterName, secondValue);
        variants.add(new IdorRequestVariant(
            label + " -> " + com.bypassfuzzer.burp.http.RequestPathUtils.pathWithoutQuery(updatedPathRequest),
            request.withPath(updatedPathRequest)
        ));
    }
}
