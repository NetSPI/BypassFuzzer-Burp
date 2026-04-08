package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.List;

/**
 * Shared JSON-body mutation helpers for playbooks that replace discovered JSON
 * identifier fields with structured values.
 */
public final class JsonBodyPlaybookSupport {

    private JsonBodyPlaybookSupport() {
    }

    public static void addJsonReplacementVariant(List<IdorRequestVariant> variants,
                                                 HttpRequest targetRequest,
                                                 LocatedParameter parameter,
                                                 String rawJsonValue,
                                                 String label) {
        HttpRequest updated = RequestParameterSupport.replaceJsonParameterValueWithJson(
            targetRequest,
            parameter,
            rawJsonValue
        );
        if (targetRequest.bodyToString().equals(updated.bodyToString())) {
            return;
        }
        variants.add(new IdorRequestVariant(parameter.path() + " " + label, updated));
    }

    public static void addDuplicateKeyVariant(List<IdorRequestVariant> variants,
                                              HttpRequest targetRequest,
                                              LocatedParameter parameter,
                                              String firstRawJsonValue,
                                              String secondRawJsonValue,
                                              String label) {
        HttpRequest updated = RequestParameterSupport.replaceJsonParameterWithDuplicateKeys(
            targetRequest,
            parameter,
            firstRawJsonValue,
            secondRawJsonValue
        );
        if (targetRequest.bodyToString().equals(updated.bodyToString())) {
            return;
        }
        variants.add(new IdorRequestVariant(parameter.path() + " " + label, updated));
    }
}
