package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.IdorRequestContext;
import com.bypassfuzzer.burp.http.LocatedParameter;

import java.util.ArrayList;
import java.util.List;

/**
 * PLAYBOOK: idor.body.json_edge_cases
 *
 * Comprehensive JSON body mutations against the identifier field. Tests
 * malformed JSON tolerance, type confusion, encoding tricks, injection
 * patterns, and structural edge cases that real parsers handle inconsistently.
 */
public class JsonEdgeCasesPlaybook implements IdorPlaybook {

    @Override
    public String id() {
        return "idor.body.json_edge_cases";
    }

    @Override
    public String displayName() {
        return "JSON Edge Cases";
    }

    @Override
    public String description() {
        return "Comprehensive JSON body mutations: malformed syntax, type confusion, "
             + "encoding tricks, injection patterns, case variants, and structural edge cases.";
    }

    @Override
    public List<IdorRequestVariant> buildVariants(IdorRequestContext context) {
        if (!context.hasJsonBodyIdentifier()) {
            return List.of();
        }

        String target = context.targetIdentifier();
        String authorized = context.authorizedIdentifier();
        if (target.isEmpty()) {
            return List.of();
        }

        HttpRequest targetRequest = context.targetRequest();
        List<IdorRequestVariant> variants = new ArrayList<>();

        for (LocatedParameter parameter : context.bodyIdentifiers()) {
            String name = parameter.name();
            String body = targetRequest.bodyToString();
            String tJson = IdorPlaybookSupport.toJsonScalar(target);

            // --- Type confusion ---
            addRawValueVariant(variants, targetRequest, body, name, tJson, "true", "boolean true");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "false", "boolean false");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "\"yes\"", "invalid boolean yes");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "\"no\"", "invalid boolean no");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "1", "numeric 1");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "0", "numeric 0");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "-1", "numeric -1");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "1.0", "float 1.0");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "\"-123\"", "negative as string");
            addRawValueVariant(variants, targetRequest, body, name, tJson, "\"1.5\"", "float as string");

            // --- Malformed JSON ---
            addRawBodyVariant(variants, targetRequest,
                body.replace("\"" + name + "\":" + tJson, "\"" + name + "\" " + tJson),
                "missing colon");
            addRawBodyVariant(variants, targetRequest,
                body.replaceFirst("\\}$", ",}"), "extra trailing comma");
            addRawBodyVariant(variants, targetRequest,
                body.replace("\"" + name + "\":" + tJson, "\"" + name + "\":"),
                "key no value");
            addRawBodyVariant(variants, targetRequest,
                body + "@@@@@}", "extra symbols after JSON");
            addRawBodyVariant(variants, targetRequest,
                body.replace("\"", "'"), "single quotes instead of double");

            // --- String manipulation ---
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"" + target.replace("", "\\n").substring(2) + "\"", "newline in value");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"\\\"" + target + "\\\"\"", "extra quotes wrapping");

            // --- Case sensitivity ---
            addKeyVariant(variants, targetRequest, body, name, name.toUpperCase(), tJson, "UPPERCASE key");
            addKeyVariant(variants, targetRequest, body, name, name.toLowerCase(), tJson, "lowercase key");
            if (name.length() > 1) {
                addKeyVariant(variants, targetRequest, body, name,
                    Character.toUpperCase(name.charAt(0)) + name.substring(1), tJson, "TitleCase key");
            }

            // --- Injection ---
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"{\\\"" + name + "\\\":\\\"" + target + "\\\"}\"", "JSON injection in string");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"${" + name.toUpperCase() + "}\"", "env var uppercase");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"${" + name + "}\"", "env var lowercase");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"${USER}\"", "env var USER");

            // --- Structural ---
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "[[" + tJson + "]]", "nested array");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "[" + tJson + ",true,1]", "mixed data types array");
            addKeyVariant(variants, targetRequest, body, name, "", tJson, "empty key");
            if (target.length() > 1) {
                addRawValueVariant(variants, targetRequest, body, name, tJson,
                    "\"" + target.charAt(0) + "\"", "single char value");
            }

            // --- Special characters in value ---
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"{" + target + "}\"", "curly braces");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"(" + target + ")\"", "parentheses");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"`" + target + "`\"", "backticks");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"" + target + "+\"", "trailing plus");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"" + target + "*\"", "trailing asterisk");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"_" + target + "\"", "leading underscore");

            // --- Unicode / encoding ---
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"" + target + "\\u200B\"", "zero-width space U+200B");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"\\u200D" + target + "\"", "zero-width joiner U+200D");
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"" + target + "\\uD83D\\uDE00\"", "emoji suffix");
            // Hex encoding of first char
            if (!target.isEmpty()) {
                addRawValueVariant(variants, targetRequest, body, name, tJson,
                    "\"\\u00" + String.format("%02x", (int) target.charAt(0)) + target.substring(1) + "\"",
                    "unicode escape first char");
            }
            // Octal-style (some parsers accept)
            addRawValueVariant(variants, targetRequest, body, name, tJson,
                "\"\\1" + target.substring(Math.min(1, target.length())) + "\"", "octal prefix");

            // --- Authorized/target combos with special shapes ---
            if (!authorized.isEmpty()) {
                addRawValueVariant(variants, targetRequest, body, name, tJson,
                    "\"" + authorized + "/../" + target + "\"", "path traversal in value");
            }
        }
        return variants;
    }

    private static void addRawValueVariant(List<IdorRequestVariant> variants,
                                           HttpRequest request,
                                           String body,
                                           String paramName,
                                           String currentValue,
                                           String newValue,
                                           String label) {
        String updated = body.replaceFirst(
            "\"" + java.util.regex.Pattern.quote(paramName) + "\"\\s*:\\s*" + java.util.regex.Pattern.quote(currentValue),
            "\"" + paramName + "\":" + newValue
        );
        if (!updated.equals(body)) {
            variants.add(new IdorRequestVariant(label, request.withBody(updated)));
        }
    }

    private static void addKeyVariant(List<IdorRequestVariant> variants,
                                      HttpRequest request,
                                      String body,
                                      String originalKey,
                                      String newKey,
                                      String value,
                                      String label) {
        String updated = body.replaceFirst(
            "\"" + java.util.regex.Pattern.quote(originalKey) + "\"",
            "\"" + newKey + "\""
        );
        if (!updated.equals(body)) {
            variants.add(new IdorRequestVariant(label, request.withBody(updated)));
        }
    }

    private static void addRawBodyVariant(List<IdorRequestVariant> variants,
                                          HttpRequest request,
                                          String newBody,
                                          String label) {
        if (!newBody.equals(request.bodyToString())) {
            variants.add(new IdorRequestVariant(label, request.withBody(newBody)));
        }
    }
}
