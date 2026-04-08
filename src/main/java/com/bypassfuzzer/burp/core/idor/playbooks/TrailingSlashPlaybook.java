package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.path.trailing_slash
 * Toggle trailing slash handling for the target request path.
 */
public class TrailingSlashPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.path.trailing_slash";
    }

    @Override
    public String displayName() {
        return "Trailing Slash";
    }

    @Override
    public String description() {
        return "Remove or add the final slash to catch path-normalization differences.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        if (!context.hasPathIdentifier()) {
            return List.of();
        }
        String path = RequestPathUtils.pathWithoutQuery(targetRequest.path());
        String query = RequestPathUtils.queryFromPath(targetRequest.path());
        if (path == null || path.isEmpty() || "/".equals(path)) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>(1);
        String updatedPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path + "/";
        if (!updatedPath.isEmpty()) {
            variants.add(new IdorRequestVariant(
                path.endsWith("/") ? "remove trailing slash" : "add trailing slash",
                targetRequest.withPath(RequestPathUtils.replaceQuery(updatedPath, query))
            ));
        }
        return variants;
    }
}
