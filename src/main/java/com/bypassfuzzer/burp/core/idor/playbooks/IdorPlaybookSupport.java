package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestBodyFormat;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Shared helpers for IDOR playbooks so path and body variants stay consistent.
 */
public final class IdorPlaybookSupport {

    private IdorPlaybookSupport() {
    }

    public static String replaceFirst(String value, String needle, String replacement) {
        if (value == null || value.isEmpty() || needle == null || needle.isEmpty()) {
            return value;
        }

        int index = value.indexOf(needle);
        if (index < 0) {
            return value;
        }
        return value.substring(0, index) + replacement + value.substring(index + needle.length());
    }

    public static void addPathVariant(List<IdorRequestVariant> variants,
                                      HttpRequest request,
                                      String updatedPath,
                                      String label) {
        if (updatedPath == null || request == null || updatedPath.equals(request.path())) {
            return;
        }
        variants.add(new IdorRequestVariant(label + " -> " + updatedPath, request.withPath(updatedPath)));
    }

    public static void addPathIdentifierValueVariants(IdorRequestContext context,
                                                      List<IdorRequestVariant> variants,
                                                      HttpRequest targetRequest,
                                                      List<String> candidates,
                                                      Function<String, String> labelBuilder) {
        String targetPath = targetRequest.path();
        String targetIdentifier = context.targetIdentifier();
        if (!context.hasPathIdentifier()
            || targetPath == null || targetPath.isEmpty()
            || targetIdentifier.isEmpty()
            || !targetPath.contains(targetIdentifier)) {
            return;
        }

        for (String candidate : candidates) {
            addPathVariant(
                variants,
                targetRequest,
                replaceFirst(targetPath, targetIdentifier, candidate),
                labelBuilder.apply(candidate)
            );
        }
    }

    public static void addBodyIdentifierValueVariants(IdorRequestContext context,
                                                      List<IdorRequestVariant> variants,
                                                      HttpRequest targetRequest,
                                                      List<String> candidates,
                                                      boolean jsonOnly,
                                                      Function<String, String> labelBuilder) {
        if (!context.hasBodyIdentifier()) {
            return;
        }
        if (jsonOnly && !context.hasJsonBodyIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            for (String candidate : candidates) {
                HttpRequest updated = jsonOnly
                    ? RequestParameterSupport.replaceJsonParameterValueWithJson(
                        targetRequest,
                        parameter,
                        toJsonScalar(candidate)
                    )
                    : RequestParameterSupport.replaceParameterValue(targetRequest, parameter, candidate);
                if (targetRequest.bodyToString().equals(updated.bodyToString())) {
                    continue;
                }
                variants.add(new IdorRequestVariant(labelBuilder.apply(parameter.path() + " -> " + candidate), updated));
            }
        }
    }

    public static void addQueryAndBodyIdentifierValueVariants(IdorRequestContext context,
                                                              List<IdorRequestVariant> variants,
                                                              HttpRequest targetRequest,
                                                              List<String> candidates,
                                                              boolean jsonBodyOnly,
                                                              BiFunction<LocatedParameter, String, String> labelBuilder) {
        if (jsonBodyOnly && !context.hasJsonBodyIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.identifierParameters()) {
            if (jsonBodyOnly) {
                if (!parameter.isBody()) {
                    continue;
                }
            } else if (parameter.location() != ParameterLocation.QUERY && !parameter.isBody()) {
                continue;
            }

            for (String candidate : candidates) {
                HttpRequest updated = parameter.isBody() && jsonBodyOnly
                    ? RequestParameterSupport.replaceJsonParameterValueWithJson(
                        targetRequest,
                        parameter,
                        toJsonScalar(candidate)
                    )
                    : RequestParameterSupport.replaceParameterValue(targetRequest, parameter, candidate);
                String before = parameter.isBody() ? targetRequest.bodyToString() : targetRequest.path();
                String after = parameter.isBody() ? updated.bodyToString() : updated.path();
                if (before.equals(after)) {
                    continue;
                }
                variants.add(new IdorRequestVariant(labelBuilder.apply(parameter, candidate), updated));
            }
        }
    }

    public static HttpRequest applyBodyFormat(HttpRequest request,
                                              String method,
                                              RequestBodyFormat format,
                                              String parameterName,
                                              String parameterValue) {
        HttpRequest preparedRequest = RequestParameterSupport.prepareForBodyFormat(request, method);
        return RequestParameterSupport.applyBodyFormat(
            preparedRequest,
            List.of(new LocatedParameter(parameterName, parameterValue, ParameterLocation.BODY)),
            format
        );
    }

    public static String bodyFormatLabel(RequestBodyFormat format) {
        return switch (format) {
            case URL_ENCODED -> "urlencoded";
            case JSON -> "json";
            case XML -> "xml";
            case MULTIPART -> "multipart";
        };
    }

    public static String jsonWrappedScalar(String parameterName, String parameterValue) {
        return "{\"" + escapeJson(parameterName) + "\":" + toJsonScalar(parameterValue) + "}";
    }

    public static String toJsonScalar(String value) {
        if (value == null) {
            return "null";
        }
        if ("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value) || "null".equalsIgnoreCase(value)) {
            return value.toLowerCase();
        }
        if (value.matches("-?\\d+(\\.\\d+)?")) {
            return value;
        }
        return "\"" + escapeJson(value) + "\"";
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
