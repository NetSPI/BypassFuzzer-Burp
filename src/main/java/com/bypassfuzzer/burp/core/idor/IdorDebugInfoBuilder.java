package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorRequestVariant;
import com.bypassfuzzer.burp.http.LocatedParameter;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a clipboard-friendly diagnostics report for the IDOR tab.
 */
public class IdorDebugInfoBuilder {

    private final IdorRequestContextAnalyzer contextAnalyzer;
    private final IdorPlaybookRegistry playbookRegistry;
    private final IdorRequestMutator requestMutator;

    public IdorDebugInfoBuilder() {
        this(new IdorRequestContextAnalyzer(), new IdorPlaybookRegistry(), new IdorRequestMutator());
    }

    IdorDebugInfoBuilder(IdorRequestContextAnalyzer contextAnalyzer,
                         IdorPlaybookRegistry playbookRegistry,
                         IdorRequestMutator requestMutator) {
        this.contextAnalyzer = contextAnalyzer;
        this.playbookRegistry = playbookRegistry;
        this.requestMutator = requestMutator;
    }

    public String build(HttpRequest originalRequest, IdorOptions options) {
        StringBuilder debug = new StringBuilder();
        debug.append("BypassFuzzer IDOR Debug Info\n");
        debug.append("Generated: ")
            .append(DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(OffsetDateTime.now()))
            .append("\n\n");

        appendRequestSection(debug, "Original Request", originalRequest);
        appendOptionsSection(debug, options, originalRequest);
        appendRegistrySection(debug);

        if (originalRequest == null) {
            debug.append("Context analysis skipped: original request is null.\n");
            return debug.toString();
        }
        if (options == null) {
            debug.append("Context analysis skipped: options are null.\n");
            return debug.toString();
        }

        String authorized = options.normalizedAuthorizedIdentifier();
        String target = options.normalizedTargetIdentifier();
        if (authorized.isEmpty() || target.isEmpty()) {
            debug.append("Context analysis skipped: identifier 1 or identifier 2 is blank.\n");
            return debug.toString();
        }

        IdorRequestContext context = contextAnalyzer.analyze(originalRequest, options);
        appendContextSection(debug, context);
        appendPlaybookVariantSection(debug, context);
        return debug.toString();
    }

    private void appendOptionsSection(StringBuilder debug, IdorOptions options, HttpRequest originalRequest) {
        debug.append("=== Inputs ===\n");
        if (options == null) {
            debug.append("Options: <null>\n\n");
            return;
        }

        String authorized = options.normalizedAuthorizedIdentifier();
        String target = options.normalizedTargetIdentifier();
        int occurrences = originalRequest == null || authorized.isEmpty()
            ? 0
            : requestMutator.countOccurrences(originalRequest, authorized);

        debug.append("Identifier 1 (authorized): ").append(displayValue(authorized)).append("\n");
        debug.append("Identifier 2 (target): ").append(displayValue(target)).append("\n");
        debug.append("Identifiers equal: ").append(authorized.equals(target)).append("\n");
        debug.append("Identifier 1 occurrences in original request: ").append(occurrences).append("\n");
        if (options.runOptions() != null) {
            debug.append("Requests/second: ").append(options.runOptions().requestsPerSecond()).append("\n");
            debug.append("Throttle status codes: ").append(options.runOptions().throttleStatusCodes()).append("\n");
        } else {
            debug.append("Run options: <null>\n");
        }
        debug.append("\n");
    }

    private void appendRegistrySection(StringBuilder debug) {
        List<IdorPlaybook> playbooks = playbookRegistry.all();
        debug.append("=== Registered Playbooks ===\n");
        debug.append("Count: ").append(playbooks.size()).append("\n");
        for (IdorPlaybook playbook : playbooks) {
            debug.append("- ")
                .append(playbook.id())
                .append(" | ")
                .append(playbook.displayName())
                .append(" | ")
                .append(playbook.description())
                .append("\n");
        }
        debug.append("\n");
    }

    private void appendContextSection(StringBuilder debug, IdorRequestContext context) {
        debug.append("=== Context Analysis ===\n");
        debug.append("Has path identifier: ").append(context.hasPathIdentifier()).append("\n");
        debug.append("Has query identifier: ").append(context.hasQueryIdentifier()).append("\n");
        debug.append("Has body identifier: ").append(context.hasBodyIdentifier()).append("\n");
        debug.append("Has JSON body identifier: ").append(context.hasJsonBodyIdentifier()).append("\n");
        debug.append("Normalized content type: ").append(displayValue(context.normalizedContentType())).append("\n");
        debug.append("Discovered identifier locations: ").append(context.identifierParameters().size()).append("\n");
        for (LocatedParameter parameter : context.identifierParameters()) {
            debug.append("- location=").append(parameter.location())
                .append(", name=").append(parameter.name())
                .append(", path=").append(parameter.path())
                .append(", occurrence=").append(parameter.occurrence())
                .append(", replacementValue=").append(displayValue(parameter.value()))
                .append("\n");
        }
        debug.append("\n");
        appendRequestSection(debug, "Target Baseline Request", context.targetRequest());
    }

    private void appendPlaybookVariantSection(StringBuilder debug, IdorRequestContext context) {
        debug.append("=== Playbook Variants ===\n");
        for (IdorPlaybook playbook : playbookRegistry.all()) {
            debug.append(playbook.id())
                .append(" | ")
                .append(playbook.displayName())
                .append("\n");
            try {
                List<IdorRequestVariant> variants = playbook.buildVariants(context);
                debug.append("Variant count: ").append(variants.size()).append("\n");
                if (variants.isEmpty()) {
                    debug.append("No variants emitted.\n\n");
                    continue;
                }

                appendDuplicateSummary(debug, variants);

                for (int i = 0; i < variants.size(); i++) {
                    IdorRequestVariant variant = variants.get(i);
                    debug.append("Variant ").append(i + 1).append(": ").append(variant.label()).append("\n");
                    appendRequestSummary(debug, variant.request());
                    debug.append("Raw request:\n")
                        .append(safeRawRequest(variant.request()))
                        .append("\n\n");
                }
            } catch (Exception e) {
                debug.append("ERROR building variants: ").append(e.getClass().getSimpleName())
                    .append(": ").append(e.getMessage()).append("\n\n");
            }
        }
    }

    private void appendDuplicateSummary(StringBuilder debug, List<IdorRequestVariant> variants) {
        Map<String, List<Integer>> rawRequestToVariants = new LinkedHashMap<>();
        for (int i = 0; i < variants.size(); i++) {
            rawRequestToVariants.computeIfAbsent(safeRawRequest(variants.get(i).request()), ignored -> new ArrayList<>())
                .add(i + 1);
        }

        debug.append("Unique effective requests: ").append(rawRequestToVariants.size()).append("\n");
        List<List<Integer>> duplicates = rawRequestToVariants.values().stream()
            .filter(indexes -> indexes.size() > 1)
            .toList();
        if (duplicates.isEmpty()) {
            debug.append("Duplicate effective requests: 0\n");
            return;
        }

        debug.append("Duplicate effective requests: ").append(duplicates.size()).append("\n");
        for (List<Integer> duplicateIndexes : duplicates) {
            debug.append("- Variants ").append(duplicateIndexes).append(" emit the same request\n");
        }
    }

    private void appendRequestSection(StringBuilder debug, String title, HttpRequest request) {
        debug.append("=== ").append(title).append(" ===\n");
        appendRequestSummary(debug, request);
        if (request != null) {
            debug.append("Raw request:\n")
                .append(safeRawRequest(request))
                .append("\n");
        }
        debug.append("\n");
    }

    private void appendRequestSummary(StringBuilder debug, HttpRequest request) {
        if (request == null) {
            debug.append("Request: <null>\n");
            return;
        }

        debug.append("Method: ").append(displayValue(request.method())).append("\n");
        debug.append("Path: ").append(displayValue(request.path())).append("\n");
        debug.append("Query: ").append(displayValue(request.query())).append("\n");
        debug.append("URL: ").append(displayValue(request.url())).append("\n");
        debug.append("Content-Type: ").append(displayValue(request.headerValue("Content-Type"))).append("\n");
        debug.append("Accept: ").append(displayValue(request.headerValue("Accept"))).append("\n");
        debug.append("Body length: ").append(request.body() == null ? 0 : request.body().length()).append("\n");
        String body = request.bodyToString();
        if (body != null && !body.isEmpty()) {
            debug.append("Body preview: ").append(preview(body, 240)).append("\n");
        }
    }

    private String safeRawRequest(HttpRequest request) {
        if (request == null) {
            return "<null>";
        }
        String raw = String.valueOf(request);
        if (raw == null || raw.isBlank()) {
            return request.method() + " " + request.path();
        }
        return raw;
    }

    private static String displayValue(String value) {
        return value == null || value.isBlank() ? "<blank>" : value;
    }

    private static String preview(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength) + "...<truncated>";
    }
}
