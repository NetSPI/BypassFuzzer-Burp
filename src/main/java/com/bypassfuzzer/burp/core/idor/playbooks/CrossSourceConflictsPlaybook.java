package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.cross_source_conflicts
 * Deliberately conflict path and query identifier sources to catch precedence bugs.
 */
public class CrossSourceConflictsPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.hybrid.cross_source_conflicts";
    }

    @Override
    public String displayName() {
        return "Cross-Source Conflicts";
    }

    @Override
    public String description() {
        return "Try path/query combinations where one source carries identifier 1 and the other carries identifier 2.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasPathIdentifier()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        String targetPath = targetRequest.path();
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (targetPath == null || targetPath.isEmpty() || authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        List<String> parameterNames = context.hasQueryIdentifier()
            ? context.queryParameterNamesOrDefaults("id", "accountId")
            : context.discoveredParameterNamesOrDefaults("id", "accountId");
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : parameterNames) {
            variants.add(variant(
                targetRequest,
                IdorPlaybookSupport.replaceFirst(targetPath, target, authorized),
                parameterName,
                authorized,
                "path=authorized query=authorized"
            ));
            variants.add(variant(
                targetRequest,
                targetPath,
                parameterName,
                authorized,
                "path=target query=authorized"
            ));
            variants.add(variant(
                targetRequest,
                IdorPlaybookSupport.replaceFirst(targetPath, target, authorized),
                parameterName,
                target,
                "path=authorized query=target"
            ));
            variants.add(variant(
                targetRequest,
                targetPath,
                parameterName,
                target,
                "path=target query=target"
            ));
        }
        return variants;
    }

    private static IdorRequestVariant variant(HttpRequest request,
                                              String path,
                                              String parameterName,
                                              String parameterValue,
                                              String label) {
        String updatedPath = QueryStringUtils.upsertDecodedParameter(path, parameterName, parameterValue);
        return new IdorRequestVariant(
            label + " (" + parameterName + "=" + parameterValue + ") -> " + RequestPathUtils.pathWithoutQuery(updatedPath),
            request.withPath(updatedPath)
        );
    }
}
