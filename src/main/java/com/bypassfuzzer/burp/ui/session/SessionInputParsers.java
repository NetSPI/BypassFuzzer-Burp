package com.bypassfuzzer.burp.ui.session;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared parsing helpers for session UI input fields.
 */
public final class SessionInputParsers {

    private SessionInputParsers() {
    }

    public static Set<Integer> parseStatusCodes(String input) {
        if (input == null || input.trim().isEmpty()) {
            return Set.of();
        }

        return java.util.Arrays.stream(input.split(","))
            .map(String::trim)
            .filter(token -> !token.isEmpty())
            .map(token -> {
                try {
                    int code = Integer.parseInt(token);
                    return code >= 100 && code < 600 ? code : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            })
            .filter(java.util.Objects::nonNull)
            .collect(Collectors.toSet());
    }
}
