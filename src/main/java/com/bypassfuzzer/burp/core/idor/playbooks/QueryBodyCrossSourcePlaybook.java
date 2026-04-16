package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.RequestBodyFormat;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.hybrid.query_body_cross_source
 *
 * Tests the cross-source disagreement between query parameters and request body.
 * An auth check might read the identifier from the query while the resolver reads
 * from the body (or vice versa). This is especially dangerous because many
 * frameworks that accept GET requests will ALSO parse a body if one is present.
 *
 * Generates variants that:
 *   - Keep query=authorized + inject body=target (the auth check sees the query,
 *     the resolver sees the body)
 *   - Keep query=target + inject body=target (both sources agree, but the auth
 *     check might fall back to session cookie instead of query)
 *   - Flip GET to POST/PUT and repeat (unlocks body parsing on frameworks that
 *     reject bodies on GET)
 *
 * Body formats tried: JSON, URL-encoded, multipart.
 */
public class QueryBodyCrossSourcePlaybook implements IdorPlaybook {

    private static final List<RequestBodyFormat> FORMATS = List.of(
        RequestBodyFormat.JSON,
        RequestBodyFormat.URL_ENCODED,
        RequestBodyFormat.MULTIPART
    );

    private static final List<String> METHODS = List.of("GET", "POST", "PUT");

    @Override
    public String id() {
        return "idor.hybrid.query_body_cross_source";
    }

    @Override
    public String displayName() {
        return "Query + Body Cross-Source";
    }

    @Override
    public String description() {
        return "Inject the target identifier into a request body while keeping " +
               "the authorized or target identifier in the query string. Tests " +
               "whether the auth check reads one source and the resolver reads " +
               "another. Tries GET, POST, and PUT with JSON, URL-encoded, and " +
               "multipart body formats.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        String authorized = context.authorizedIdentifier();
        String target = context.targetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            return List.of();
        }

        // Need at least one query or body identifier to know the parameter name.
        if (!context.hasQueryIdentifier() && !context.hasBodyIdentifier()) {
            return List.of();
        }

        // Determine the parameter name from the discovered identifier location.
        String paramName = context.discoveredParameterNamesOrDefaults("id").get(0);
        HttpRequest targetRequest = context.targetRequest();
        String originalMethod = targetRequest.method();

        List<IdorRequestVariant> variants = new ArrayList<>();

        for (String method : METHODS) {
            for (RequestBodyFormat format : FORMATS) {
                String formatLabel = IdorPlaybookSupport.bodyFormatLabel(format);

                // Variant A: query=authorized, body=target
                // Auth check reads query (sees authorized → passes), resolver reads body (sees target).
                HttpRequest variantA = withQueryAndBody(targetRequest, method, paramName, authorized, target, format);
                variants.add(new IdorRequestVariant(
                    method + " query " + paramName + "=" + authorized + " + " + formatLabel + " body " + paramName + "=" + target,
                    variantA
                ));

                // Variant B: query=target, body=target (both agree, body present)
                // Tests if adding a body changes routing even when query already has target.
                if (!method.equals(originalMethod) || format != RequestBodyFormat.URL_ENCODED) {
                    HttpRequest variantB = withQueryAndBody(targetRequest, method, paramName, target, target, format);
                    variants.add(new IdorRequestVariant(
                        method + " query " + paramName + "=" + target + " + " + formatLabel + " body " + paramName + "=" + target,
                        variantB
                    ));
                }
            }
        }

        // Reverse: if the original has a body identifier but no query,
        // try moving the identifier INTO the query (stripping the body).
        if (context.hasBodyIdentifier() && !context.hasQueryIdentifier()) {
            String pathWithQuery = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(
                targetRequest.path(), paramName, target
            );
            HttpRequest queryOnly = targetRequest.withPath(pathWithQuery).withBody("").withRemovedHeader("Content-Type");
            variants.add(new IdorRequestVariant(
                "body→query: " + paramName + "=" + target + " (body removed)",
                queryOnly
            ));
        }

        return variants;
    }

    private static HttpRequest withQueryAndBody(HttpRequest request,
                                                String method,
                                                String paramName,
                                                String queryValue,
                                                String bodyValue,
                                                RequestBodyFormat format) {
        // Set the query parameter value
        String updatedPath = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(
            request.path(), paramName, queryValue
        );

        // Apply the body format with the target identifier
        HttpRequest updated = request.withPath(updatedPath).withMethod(method);
        return IdorPlaybookSupport.applyBodyFormat(updated, method, format, paramName, bodyValue);
    }
}
