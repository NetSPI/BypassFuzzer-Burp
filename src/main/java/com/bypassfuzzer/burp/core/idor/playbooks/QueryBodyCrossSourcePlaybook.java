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

                // A: query=authorized, body=target
                variants.add(new IdorRequestVariant(
                    method + " query=" + authorized + " + " + formatLabel + " body=" + target,
                    withQueryAndBody(targetRequest, method, paramName, authorized, target, format)
                ));

                // A flipped: query=target, body=authorized
                variants.add(new IdorRequestVariant(
                    method + " query=" + target + " + " + formatLabel + " body=" + authorized,
                    withQueryAndBody(targetRequest, method, paramName, target, authorized, format)
                ));

                // B: body=target only (no query)
                variants.add(new IdorRequestVariant(
                    method + " " + formatLabel + " body=" + target + " (no query)",
                    bodyOnly(targetRequest, method, paramName, target, format)
                ));

                // B flipped: body=authorized only (no query)
                variants.add(new IdorRequestVariant(
                    method + " " + formatLabel + " body=" + authorized + " (no query)",
                    bodyOnly(targetRequest, method, paramName, authorized, format)
                ));
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

        // Path injection: even if the original request has the identifier in
        // query or body, the app might ALSO accept it from the URL path.
        // Some frameworks route /resource/<id> and /resource?id=<id> to the
        // same handler. Try injecting both identifiers as path segments.
        String basePath = com.bypassfuzzer.burp.http.RequestPathUtils.pathWithoutQuery(targetRequest.path());
        if (!basePath.endsWith("/")) basePath += "/";

        for (String id : List.of(target, authorized)) {
            // /my-account/carlos
            variants.add(new IdorRequestVariant(
                "path=" + id + " (appended to path)",
                targetRequest.withPath(basePath + id)
            ));
            // /my-account/id/carlos
            variants.add(new IdorRequestVariant(
                "path=/" + paramName + "/" + id,
                targetRequest.withPath(basePath + paramName + "/" + id)
            ));
            // /my-account/carlos + query=authorized (cross-source: path vs query)
            String otherValue = id.equals(target) ? authorized : target;
            String pathWithQuery = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                basePath + id, paramName, otherValue);
            variants.add(new IdorRequestVariant(
                "path=" + id + " + query=" + otherValue,
                targetRequest.withPath(pathWithQuery)
            ));
            // /my-account/id/carlos + query=authorized
            String paramPathWithQuery = com.bypassfuzzer.burp.http.QueryStringUtils.appendDecodedParameter(
                basePath + paramName + "/" + id, paramName, otherValue);
            variants.add(new IdorRequestVariant(
                "path=/" + paramName + "/" + id + " + query=" + otherValue,
                targetRequest.withPath(paramPathWithQuery)
            ));
        }

        return variants;
    }

    private static HttpRequest bodyOnly(HttpRequest request,
                                       String method,
                                       String paramName,
                                       String bodyValue,
                                       RequestBodyFormat format) {
        return IdorPlaybookSupport.applyBodyFormat(request, method, format, paramName, bodyValue);
    }

    private static HttpRequest withQueryAndBody(HttpRequest request,
                                                String method,
                                                String paramName,
                                                String queryValue,
                                                String bodyValue,
                                                RequestBodyFormat format) {
        // Apply the body format first (this may strip query params via
        // prepareForBodyFormat), then re-add the query parameter so both
        // sources are present in the final request.
        HttpRequest withBody = IdorPlaybookSupport.applyBodyFormat(
            request, method, format, paramName, bodyValue
        );
        String pathWithQuery = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(
            withBody.path(), paramName, queryValue
        );
        return withBody.withPath(pathWithQuery);
    }
}
