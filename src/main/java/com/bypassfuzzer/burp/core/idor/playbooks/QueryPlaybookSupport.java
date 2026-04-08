package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.QueryStringUtils;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared helpers for query-oriented IDOR playbooks so they resolve parameter
 * names and construct variants consistently.
 */
public final class QueryPlaybookSupport {

    private QueryPlaybookSupport() {
    }

    public static List<String> parameterNames(IdorRequestContext context, List<String> defaults) {
        if (context.hasQueryIdentifier()) {
            return context.queryParameterNamesOrDefaults(defaults.toArray(String[]::new));
        }
        return context.discoveredParameterNamesOrDefaults(defaults.toArray(String[]::new));
    }

    public static List<String> mergedParameterNames(IdorRequestContext context, List<String> extras) {
        Set<String> names = new LinkedHashSet<>(context.discoveredParameterNamesOrDefaults());
        names.addAll(extras);
        return List.copyOf(names);
    }

    public static void addUpsertVariant(List<IdorRequestVariant> variants,
                                        HttpRequest request,
                                        String parameterName,
                                        String parameterValue,
                                        String label) {
        String updatedPath = QueryStringUtils.upsertDecodedParameter(request.path(), parameterName, parameterValue);
        variants.add(new IdorRequestVariant(
            label + " -> " + RequestPathUtils.pathWithoutQuery(updatedPath),
            request.withPath(updatedPath)
        ));
    }

    public static void addAppendVariant(List<IdorRequestVariant> variants,
                                        HttpRequest request,
                                        String parameterName,
                                        String parameterValue,
                                        String label) {
        String updatedPath = QueryStringUtils.appendDecodedParameter(request.path(), parameterName, parameterValue);
        variants.add(new IdorRequestVariant(
            label + " -> " + RequestPathUtils.pathWithoutQuery(updatedPath),
            request.withPath(updatedPath)
        ));
    }
}
