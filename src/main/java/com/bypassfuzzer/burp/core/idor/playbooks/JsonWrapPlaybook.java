package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.json_wrap
 * Wrap identifier values inside nested JSON objects to probe parser confusion and object binding edge cases.
 */
public class JsonWrapPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.json_wrap";
    }

    @Override
    public String displayName() {
        return "JSON Wrap";
    }

    @Override
    public String description() {
        return "Wrap likely identifier fields as nested JSON objects, such as {\"id\":{\"id\":\"target\"}}.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            String wrappedBody = "{\"" + parameter.name() + "\":" + IdorPlaybookSupport.jsonWrappedScalar(parameter.name(), parameter.value()) + "}";
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                IdorPlaybookSupport.jsonWrappedScalar(parameter.name(), parameter.value()),
                "wrap -> " + wrappedBody
            );
        }
        return variants;
    }
}
