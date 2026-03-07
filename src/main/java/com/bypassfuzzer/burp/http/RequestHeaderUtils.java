package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Helpers for replacing existing headers instead of blindly creating duplicates.
 */
public final class RequestHeaderUtils {

    private static final String COOKIE_HEADER = "Cookie";

    public enum AttackHeaderMutationMode {
        OVERWRITE,
        APPEND_PRESERVE_EXISTING
    }

    private RequestHeaderUtils() {
    }

    public static HttpRequest upsertHeader(HttpRequest request, String headerName, String headerValue) {
        if (request.hasHeader(headerName)) {
            return request.withUpdatedHeader(headerName, headerValue);
        }
        return request.withAddedHeader(headerName, headerValue);
    }

    /**
     * Apply a fuzzing header mutation using semantics that preserve authenticated context where appropriate.
     * Cookie headers keep the original session value and append the fuzz payload; other headers overwrite by name.
     */
    public static HttpRequest applyAttackHeader(HttpRequest request, String headerName, String headerValue) {
        return switch (attackHeaderMutationMode(headerName)) {
            case APPEND_PRESERVE_EXISTING -> {
                String existingCookie = request.headerValue(COOKIE_HEADER);
                if (existingCookie != null && !existingCookie.isEmpty()) {
                    yield request.withUpdatedHeader(COOKIE_HEADER, existingCookie + "; " + headerValue);
                }
                yield upsertHeader(request, headerName, headerValue);
            }
            case OVERWRITE -> upsertHeader(request, headerName, headerValue);
        };
    }

    public static AttackHeaderMutationMode attackHeaderMutationMode(String headerName) {
        if (COOKIE_HEADER.equalsIgnoreCase(headerName)) {
            return AttackHeaderMutationMode.APPEND_PRESERVE_EXISTING;
        }
        return AttackHeaderMutationMode.OVERWRITE;
    }
}
