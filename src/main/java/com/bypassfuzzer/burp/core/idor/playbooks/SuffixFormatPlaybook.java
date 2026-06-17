package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;
import com.bypassfuzzer.burp.http.LocatedParameter;
import com.bypassfuzzer.burp.http.RequestPathUtils;
import com.bypassfuzzer.burp.http.RequestParameterSupport;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PLAYBOOK: idor.path.suffix_formats
 * Try format-like suffixes on the target identifier and version segment.
 */
public class SuffixFormatPlaybook implements IdorPlaybook {

    private static final List<String> FORMAT_SUFFIXES = List.of(".json", ".html");
    private static final List<String> PATH_IDENTIFIER_SUFFIXES = pathIdentifierSuffixes();
    private static final List<String> VERSION_SUFFIXES = pathVersionSuffixes();

    @Override
    public String id() {
        return "idor.path.suffix_formats";
    }

    @Override
    public String displayName() {
        return "Suffix Formats";
    }

    @Override
    public String description() {
        return "Try format and matrix-extension suffixes on discovered path identifiers, plus lightweight .json/.html suffixes in query and body locations.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        HttpRequest targetRequest = context.targetRequest();
        String targetPath = targetRequest.path();
        String targetIdentifier = context.targetIdentifier();
        if (targetIdentifier.isEmpty()) {
            return List.of();
        }

        List<IdorRequestVariant> variants = new ArrayList<>();
        addPathVariants(context, variants, targetRequest, targetPath, targetIdentifier);
        addQueryVariants(context, variants, targetRequest, targetIdentifier);
        addBodyVariants(context, variants, targetRequest);

        return variants;
    }

    private static void addPathVariants(IdorRequestContext context,
                                        List<IdorRequestVariant> variants,
                                        HttpRequest targetRequest,
                                        String targetPath,
                                        String targetIdentifier) {
        if (!context.hasPathIdentifier()
            || targetPath == null || targetPath.isEmpty()
            || !targetPath.contains(targetIdentifier)) {
            return;
        }

        Set<String> seenPaths = new LinkedHashSet<>();

        for (String suffix : PATH_IDENTIFIER_SUFFIXES) {
            addDistinctPathVariant(
                variants,
                seenPaths,
                targetRequest,
                IdorPlaybookSupport.replaceFirst(targetPath, targetIdentifier, targetIdentifier + suffix),
                "identifier" + suffix
            );
        }

        for (String suffix : VERSION_SUFFIXES) {
            addDistinctPathVariant(
                variants,
                seenPaths,
                targetRequest,
                suffixLastPathSegment(targetPath, suffix),
                "version" + suffix
            );
        }

        for (String suffix : VERSION_SUFFIXES) {
            String updatedIdentifierPath = IdorPlaybookSupport.replaceFirst(targetPath, targetIdentifier, targetIdentifier + suffix);
            String updatedBothPath = suffixLastPathSegment(updatedIdentifierPath, suffix);
            addDistinctPathVariant(variants, seenPaths, targetRequest, updatedBothPath, "identifier+version" + suffix);
        }
    }

    private static void addQueryVariants(IdorRequestContext context,
                                         List<IdorRequestVariant> variants,
                                         HttpRequest targetRequest,
                                         String targetIdentifier) {
        if (!context.hasQueryIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.queryIdentifiers()) {
            for (String suffix : FORMAT_SUFFIXES) {
                String value = targetIdentifier + suffix;
                String updatedPath = com.bypassfuzzer.burp.http.QueryStringUtils.upsertDecodedParameter(
                    targetRequest.path(), parameter.name(), value
                );
                variants.add(new IdorRequestVariant(
                    "query " + parameter.name() + " -> " + value,
                    targetRequest.withPath(updatedPath)
                ));
            }
        }
    }

    private static void addBodyVariants(IdorRequestContext context,
                                        List<IdorRequestVariant> variants,
                                        HttpRequest targetRequest) {
        if (!context.hasBodyIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            for (String suffix : FORMAT_SUFFIXES) {
                String candidate = parameter.value() + suffix;
                HttpRequest updated = RequestParameterSupport.replaceParameterValue(targetRequest, parameter, candidate);
                if (!updated.bodyToString().equals(targetRequest.bodyToString())) {
                    variants.add(new IdorRequestVariant("body " + parameter.path() + " " + suffix, updated));
                }
            }
        }
    }

    private static String suffixLastPathSegment(String pathWithQuery, String suffix) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        boolean trailingSlash = path.endsWith("/");
        String workingPath = trailingSlash && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
        int lastSlash = workingPath.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == workingPath.length() - 1) {
            return pathWithQuery;
        }

        String updatedPath = workingPath + suffix;
        if (trailingSlash) {
            updatedPath += "/";
        }
        return RequestPathUtils.replaceQuery(updatedPath, query);
    }

    private static void addDistinctPathVariant(List<IdorRequestVariant> variants,
                                               Set<String> seenPaths,
                                               HttpRequest targetRequest,
                                               String updatedPath,
                                               String label) {
        if (!seenPaths.add(updatedPath)) {
            return;
        }
        IdorPlaybookSupport.addPathVariant(variants, targetRequest, updatedPath, label);
    }

    private static List<String> pathIdentifierSuffixes() {
        Set<String> suffixes = new LinkedHashSet<>(FORMAT_SUFFIXES);
        suffixes.addAll(matrixFormatSuffixes());
        return new ArrayList<>(suffixes);
    }

    private static List<String> pathVersionSuffixes() {
        Set<String> suffixes = new LinkedHashSet<>(List.of(".json"));
        suffixes.addAll(matrixFormatSuffixes());
        return new ArrayList<>(suffixes);
    }

    private static List<String> matrixFormatSuffixes() {
        Set<String> suffixes = new LinkedHashSet<>();
        for (String extension : loadExtensionSuffixes()) {
            suffixes.add(";" + extension);
            suffixes.add("%3b" + extension);
            suffixes.add(extension + ";");
            suffixes.add(extension + ";jsessionid=1");
            suffixes.add(extension + ";foo=bar");
        }
        return new ArrayList<>(suffixes);
    }

    private static List<String> loadExtensionSuffixes() {
        Set<String> extensions = new LinkedHashSet<>();
        try {
            PayloadLoader.loadPayloads("extension_payloads.txt").stream()
                .filter(extension -> extension != null && !extension.isBlank())
                .map(String::trim)
                .map(extension -> extension.startsWith(".") ? extension : "." + extension)
                .forEach(extensions::add);
        } catch (RuntimeException e) {
            extensions.addAll(List.of(".json", ".html", ".xml", ".txt", ".php"));
        }
        extensions.addAll(List.of(".jpeg", ".jpg", ".png", ".gif", ".css", ".js"));
        return new ArrayList<>(extensions);
    }
}
