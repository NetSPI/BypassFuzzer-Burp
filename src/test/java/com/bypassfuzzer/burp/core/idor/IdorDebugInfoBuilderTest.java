package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorRequestVariant;
import com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

class IdorDebugInfoBuilderTest {

    private final IdorRequestContextAnalyzer contextAnalyzer = new IdorRequestContextAnalyzer(
        new IdorRequestMutator((service, rawRequest) -> HttpRequestTestFactory.fromRawRequest(rawRequest))
    );

    private final IdorRequestMutator requestMutator = new IdorRequestMutator(
        (service, rawRequest) -> HttpRequestTestFactory.fromRawRequest(rawRequest)
    );

    @Test
    void debugInfoIncludesContextAndPerPlaybookVariants() {
        HttpRequest originalRequest = HttpRequestTestFactory.request("/accounts/abc123", "id=abc123", "GET", null, "");
        HttpRequest variantRequest = HttpRequestTestFactory.request("/accounts/def456", "id=abc123", "GET", null, "");

        IdorPlaybookRegistry registry = new IdorPlaybookRegistry() {
            @Override
            public List<IdorPlaybook> all() {
                return List.of(new IdorPlaybook() {
                    @Override
                    public String id() {
                        return "idor.test.synthetic";
                    }

                    @Override
                    public String displayName() {
                        return "Synthetic";
                    }

                    @Override
                    public String description() {
                        return "Synthetic test playbook";
                    }

                    @Override
                    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
                        return List.of(
                            new IdorRequestVariant("query override", variantRequest),
                            new IdorRequestVariant("same query override", variantRequest)
                        );
                    }
                });
            }
        };

        IdorDebugInfoBuilder builder = new IdorDebugInfoBuilder(contextAnalyzer, registry, requestMutator);

        String debugInfo = builder.build(
            originalRequest,
            new IdorOptions("abc123", "def456", new IdorRunOptions(2, Set.of(429, 503)))
        );

        assertTrue(debugInfo.contains("Identifier 1 (authorized): abc123"), debugInfo);
        assertTrue(debugInfo.contains("Identifier 2 (target): def456"), debugInfo);
        assertTrue(debugInfo.contains("Identifier 1 occurrences in original request: 2"), debugInfo);
        assertTrue(debugInfo.contains("Has path identifier: true"), debugInfo);
        assertTrue(debugInfo.contains("Has query identifier: true"), debugInfo);
        assertTrue(debugInfo.contains("location=QUERY, name=id"), debugInfo);
        assertTrue(debugInfo.contains("idor.test.synthetic | Synthetic"), debugInfo);
        assertTrue(debugInfo.contains("Variant count: 2"), debugInfo);
        assertTrue(debugInfo.contains("Unique effective requests: 1"), debugInfo);
        assertTrue(debugInfo.contains("Duplicate effective requests: 1"), debugInfo);
        assertTrue(debugInfo.contains("Variants [1, 2] emit the same request"), debugInfo);
        assertTrue(debugInfo.contains("Variant 1: query override"), debugInfo);
        assertTrue(debugInfo.contains("GET /accounts/def456?id=abc123 HTTP/1.1"), debugInfo);
    }
}
