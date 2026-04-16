package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.query.numeric_pivots
 * Probe common numeric identifier pivots in query parameters, even when the visible identifier looks opaque.
 */
public class NumericPivotsPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of("id", "accountId");
    private static final List<String> CANDIDATES = List.of("0", "1", "2", "3", "-1");

    @Override
    public String id() {
        return "idor.query.numeric_pivots";
    }

    @Override
    public String displayName() {
        return "Numeric Pivots";
    }

    @Override
    public String description() {
        return "Try common numeric pivots such as 0, 1, 2, 3, and -1 in likely identifier parameters.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : QueryPlaybookSupport.parameterNames(context, PARAMETER_NAMES)) {
            for (String candidate : CANDIDATES) {
                QueryPlaybookSupport.addUpsertVariant(
                    variants,
                    targetRequest,
                    parameterName,
                    candidate,
                    parameterName + "=" + candidate
                );
            }
        }
        // Also try numeric pivots in JSON body identifiers
        IdorPlaybookSupport.addQueryAndBodyIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            CANDIDATES,
            false,
            (parameter, candidate) ->
                parameter.location().name().toLowerCase() + " " + parameter.path() + " -> " + candidate
        );
        return variants;
    }
}
