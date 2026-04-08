package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.ParameterLocation;
import com.bypassfuzzer.burp.http.RequestPathUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Context derived from the user's authorized request and identifiers.
 *
 * Playbooks should use this context instead of assuming the identifier only appears in the path.
 */
public record IdorRequestContext(
    HttpRequest originalRequest,
    HttpRequest targetRequest,
    IdorOptions options,
    List<LocatedParameter> identifierParameters
) {

    public String authorizedIdentifier() {
        return options.normalizedAuthorizedIdentifier();
    }

    public String targetIdentifier() {
        return options.normalizedTargetIdentifier();
    }

    public boolean hasPathIdentifier() {
        String path = RequestPathUtils.pathWithoutQuery(originalRequest.path());
        String authorized = authorizedIdentifier();
        return path != null && !path.isEmpty() && !authorized.isEmpty() && path.contains(authorized);
    }

    public List<LocatedParameter> queryIdentifiers() {
        return identifierParameters.stream()
            .filter(parameter -> parameter.location() == ParameterLocation.QUERY)
            .toList();
    }

    public List<LocatedParameter> bodyIdentifiers() {
        return identifierParameters.stream()
            .filter(LocatedParameter::isBody)
            .toList();
    }

    public boolean hasQueryIdentifier() {
        return !queryIdentifiers().isEmpty();
    }

    public boolean hasBodyIdentifier() {
        return !bodyIdentifiers().isEmpty();
    }

    public boolean hasJsonBodyIdentifier() {
        String contentType = normalizedContentType();
        return contentType.contains("application/json") && hasBodyIdentifier();
    }

    public String normalizedContentType() {
        String contentType = targetRequest.headerValue("Content-Type");
        return contentType == null ? "" : contentType.toLowerCase();
    }

    public List<String> queryParameterNamesOrDefaults(String... defaults) {
        return namesOrDefaults(queryIdentifiers(), defaults);
    }

    public List<String> bodyParameterNamesOrDefaults(String... defaults) {
        return namesOrDefaults(bodyIdentifiers(), defaults);
    }

    public List<String> discoveredParameterNamesOrDefaults(String... defaults) {
        return namesOrDefaults(identifierParameters, defaults);
    }

    private List<String> namesOrDefaults(List<LocatedParameter> parameters, String... defaults) {
        Set<String> names = new LinkedHashSet<>();
        for (LocatedParameter parameter : parameters) {
            names.add(parameter.name());
        }
        if (names.isEmpty()) {
            java.util.Collections.addAll(names, defaults);
        }
        return new ArrayList<>(names);
    }
}
