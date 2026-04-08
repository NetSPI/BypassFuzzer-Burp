package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.RequestBodyFormat;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * PLAYBOOK: idor.body.content_type_tampering
 * Re-express likely object identifier parameters in different body formats to probe parser and routing differences.
 */
public class ContentTypeTamperingPlaybook implements IdorPlaybook {

    private static final List<String> PARAMETER_NAMES = List.of("id", "accountId");
    private static final List<RequestBodyFormat> FORMATS = List.of(
        RequestBodyFormat.URL_ENCODED,
        RequestBodyFormat.JSON,
        RequestBodyFormat.XML,
        RequestBodyFormat.MULTIPART
    );

    @Override
    public String id() {
        return "idor.body.content_type_tampering";
    }

    @Override
    public String displayName() {
        return "Content-Type Tampering";
    }

    @Override
    public String description() {
        return "Try moving the target identifier into URL-encoded, JSON, XML, and multipart request bodies, including header/body mismatches.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String target = context.targetIdentifier();
        if (target.isEmpty() || !context.hasBodyIdentifier()) {
            return List.of();
        }

        String method = RequestParameterSupport.supportsBody(targetRequest.method()) ? targetRequest.method() : "POST";
        List<IdorRequestVariant> variants = new ArrayList<>();
        for (String parameterName : context.bodyParameterNamesOrDefaults(PARAMETER_NAMES.toArray(String[]::new))) {
            for (RequestBodyFormat format : FORMATS) {
                HttpRequest updated = IdorPlaybookSupport.applyBodyFormat(targetRequest, method, format, parameterName, target);
                variants.add(new IdorRequestVariant(
                    IdorPlaybookSupport.bodyFormatLabel(format) + " body " + parameterName + "=" + target,
                    updated
                ));
                if (hasOriginalBody(targetRequest)) {
                    variants.add(new IdorRequestVariant(
                        "mismatch declared " + IdorPlaybookSupport.bodyFormatLabel(format) + " for original body",
                        prepareBodyCarrier(targetRequest, method).withUpdatedHeader("Content-Type", contentTypeFor(format))
                    ));
                }
            }
            variants.add(new IdorRequestVariant(
                "multipart nested-urlencoded part " + parameterName + "=" + target,
                nestedMultipartUrlEncoded(targetRequest, method, parameterName, target)
            ));
        }
        return variants;
    }

    private static boolean hasOriginalBody(HttpRequest request) {
        return request.body() != null && request.body().length() > 0;
    }

    private static HttpRequest prepareBodyCarrier(HttpRequest request, String method) {
        return RequestParameterSupport.prepareForBodyFormat(request, method).withMethod(method);
    }

    private static String contentTypeFor(RequestBodyFormat format) {
        return switch (format) {
            case URL_ENCODED -> "application/x-www-form-urlencoded";
            case JSON -> "application/json";
            case XML -> "application/xml";
            case MULTIPART -> "multipart/form-data; boundary=xbfuzz";
        };
    }

    private static HttpRequest nestedMultipartUrlEncoded(HttpRequest request,
                                                         String method,
                                                         String parameterName,
                                                         String targetIdentifier) {
        String boundary = "----BypassFuzzer" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String body = "--" + boundary + "\r\n"
            + "Content-Type: application/x-www-form-urlencoded\r\n"
            + "Content-Disposition: form-data; name=\"" + parameterName + "\"\r\n\r\n"
            + parameterName + "=" + targetIdentifier + "\r\n"
            + "--" + boundary + "--\r\n";

        return prepareBodyCarrier(request, method)
            .withUpdatedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
            .withBody(body);
    }
}
