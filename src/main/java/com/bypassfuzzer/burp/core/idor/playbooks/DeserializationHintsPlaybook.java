package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.deserialization_hints
 * Wrap JSON identifier values in object structures that include type hints or
 * prototype-like fields to probe deserializer-specific object resolution.
 */
public class DeserializationHintsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.deserialization_hints";
    }

    @Override
    public String displayName() {
        return "Deserialization Hints";
    }

    @Override
    public String description() {
        return "Wrap JSON IDs in type-hinted or prototype-like objects to probe deserializer-specific object binding.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                typedWrapper("@type", parameter.name(), parameter.value()),
                "typed wrapper @type"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                typedWrapper("@class", parameter.name(), parameter.value()),
                "typed wrapper @class"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                typedWrapper("$type", parameter.name(), parameter.value()),
                "typed wrapper $type"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                typedWrapper("_class", parameter.name(), parameter.value()),
                "typed wrapper _class"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "{\"__proto__\":{" + jsonEntry(parameter.name(), parameter.value()) + "}}",
                "__proto__ wrapper"
            );
            JsonBodyPlaybookSupport.addJsonReplacementVariant(
                variants,
                targetRequest,
                parameter,
                "{\"constructor\":{\"prototype\":{" + jsonEntry(parameter.name(), parameter.value()) + "}}}",
                "constructor prototype wrapper"
            );
        }
        return variants;
    }

    private static String typedWrapper(String hintField, String fieldName, String fieldValue) {
        return "{"
            + jsonEntry(hintField, "java.lang.String") + ","
            + jsonEntry(fieldName, fieldValue)
            + "}";
    }

    private static String jsonEntry(String fieldName, String fieldValue) {
        return "\"" + escapeJson(fieldName) + "\":" + IdorPlaybookSupport.toJsonScalar(fieldValue);
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
