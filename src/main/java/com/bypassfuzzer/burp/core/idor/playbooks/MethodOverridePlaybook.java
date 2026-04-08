package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.RequestHeaderUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.method_override
 * Borrow high-signal method and method-override ideas from the bypass tab.
 */
public class MethodOverridePlaybook implements IdorPlaybook {

    private static final List<String> DIRECT_METHODS = List.of("HEAD", "POST", "PUT", "PATCH", "DELETE");
    private static final List<String> OVERRIDE_HEADERS = List.of(
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override"
    );
    private static final List<String> OVERRIDE_METHODS = List.of("GET", "DELETE", "PATCH");

    @Override
    public String id() {
        return "idor.hybrid.method_override";
    }

    @Override
    public String displayName() {
        return "Method Override";
    }

    @Override
    public String description() {
        return "Try direct CRUD methods and curated method-override headers against identifier 2.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();
        String originalMethod = targetRequest.method() == null ? "GET" : targetRequest.method();

        for (String method : DIRECT_METHODS) {
            if (!method.equalsIgnoreCase(originalMethod)) {
                variants.add(new IdorRequestVariant("direct method " + method, targetRequest.withMethod(method)));
            }
        }

        for (String header : OVERRIDE_HEADERS) {
            for (String method : OVERRIDE_METHODS) {
                HttpRequest updated = RequestHeaderUtils.upsertHeader(targetRequest, header, method);
                variants.add(new IdorRequestVariant(header + "=" + method, updated));
            }
        }

        for (String header : OVERRIDE_HEADERS) {
            for (String overrideMethod : OVERRIDE_METHODS) {
                HttpRequest updated = RequestHeaderUtils.upsertHeader(targetRequest.withMethod("POST"), header, overrideMethod);
                variants.add(new IdorRequestVariant("POST + " + header + "=" + overrideMethod, updated));
            }
        }

        return variants;
    }
}
