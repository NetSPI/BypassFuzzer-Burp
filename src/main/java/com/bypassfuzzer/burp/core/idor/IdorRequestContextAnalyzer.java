package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.List;

/**
 * Discovers where the authorized identifier appears so playbooks can mutate the right request context.
 */
public class IdorRequestContextAnalyzer {

    private final IdorRequestMutator requestMutator;

    public IdorRequestContextAnalyzer() {
        this(new IdorRequestMutator());
    }

    IdorRequestContextAnalyzer(IdorRequestMutator requestMutator) {
        this.requestMutator = requestMutator;
    }

    public IdorRequestContext analyze(HttpRequest request, IdorOptions options) {
        String authorizedIdentifier = options.normalizedAuthorizedIdentifier();
        String targetIdentifier = options.normalizedTargetIdentifier();
        HttpRequest targetRequest = requestMutator.replaceIdentifier(request, authorizedIdentifier, targetIdentifier);

        List<LocatedParameter> identifierParameters = RequestParameterSupport.extractLocatedParameters(request).stream()
            .filter(parameter -> authorizedIdentifier.equals(parameter.value()))
            .map(parameter -> new LocatedParameter(
                parameter.name(),
                targetIdentifier,
                parameter.location(),
                parameter.path(),
                parameter.occurrence()
            ))
            .toList();

        return new IdorRequestContext(request, targetRequest, options, identifierParameters);
    }
}
