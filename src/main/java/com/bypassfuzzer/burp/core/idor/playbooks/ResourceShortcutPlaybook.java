package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.resource_shortcuts
 * Try semantic identifier shortcuts like me/all/self in discovered identifier locations.
 */
public class ResourceShortcutPlaybook implements IdorPlaybook {

    private static final List<String> PATH_CANDIDATES = List.of("me", "self", "all");
    private static final List<String> VALUE_CANDIDATES = List.of("me", "self", "all", "/me", "/self", "/all");

    @Override
    public String id() {
        return "idor.hybrid.resource_shortcuts";
    }

    @Override
    public String displayName() {
        return "Resource Shortcuts";
    }

    @Override
    public String description() {
        return "Try semantic shortcuts like me, self, all, /me, and /all in discovered identifier locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (context.targetIdentifier().isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();

        IdorPlaybookSupport.addPathIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            PATH_CANDIDATES,
            candidate -> "path " + candidate
        );
        IdorPlaybookSupport.addQueryAndBodyIdentifierValueVariants(
            context,
            variants,
            targetRequest,
            VALUE_CANDIDATES,
            false,
            (parameter, candidate) -> parameter.location().name().toLowerCase() + " " + parameter.path() + " -> " + candidate
        );

        return variants;
    }
}
