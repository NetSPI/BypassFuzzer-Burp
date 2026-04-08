package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
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

    private static final List<String> IDENTIFIER_SUFFIXES = List.of(".json", ".html");
    private static final List<String> VERSION_SUFFIXES = List.of(".json");

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
        return "Try .json/.html suffixes on discovered identifier locations and on the terminal version segment when the identifier lives in the path.";
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

        for (String suffix : IDENTIFIER_SUFFIXES) {
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

    private static void addBodyVariants(IdorRequestContext context,
                                        List<IdorRequestVariant> variants,
                                        HttpRequest targetRequest) {
        if (!context.hasBodyIdentifier()) {
            return;
        }

        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            for (String suffix : IDENTIFIER_SUFFIXES) {
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
}
