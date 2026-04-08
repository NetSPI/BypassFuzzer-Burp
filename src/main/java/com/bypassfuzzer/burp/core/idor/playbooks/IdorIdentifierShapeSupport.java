package com.bypassfuzzer.burp.core.idor.playbooks;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Shared identifier-shape helpers for UUID-like and hex-like IDOR playbooks.
 */
public final class IdorIdentifierShapeSupport {

    private static final Pattern HYPHENATED_UUID = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
    private static final Pattern BRACED_UUID = Pattern.compile(
        "^\\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}$"
    );
    private static final Pattern COMPACT_UUID = Pattern.compile("^[0-9a-fA-F]{32}$");
    private static final Pattern HEX_OPAQUE = Pattern.compile("^[0-9a-fA-F]{6,64}$");

    private IdorIdentifierShapeSupport() {
    }

    public static IdentifierShape detect(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        if (BRACED_UUID.matcher(value).matches()) {
            String inner = value.substring(1, value.length() - 1);
            return new IdentifierShape(IdentifierKind.UUID_BRACED, normalizeCase(inner.replace("-", "")), prefersUppercase(inner));
        }
        if (HYPHENATED_UUID.matcher(value).matches()) {
            return new IdentifierShape(IdentifierKind.UUID_HYPHENATED, normalizeCase(value.replace("-", "")), prefersUppercase(value));
        }
        if (COMPACT_UUID.matcher(value).matches()) {
            return new IdentifierShape(IdentifierKind.UUID_COMPACT, normalizeCase(value), prefersUppercase(value));
        }
        if (HEX_OPAQUE.matcher(value).matches()) {
            return new IdentifierShape(IdentifierKind.HEX_OPAQUE, normalizeCase(value), prefersUppercase(value));
        }
        return null;
    }

    public static List<String> canonicalUuidCandidates(String value) {
        IdentifierShape shape = detect(value);
        if (shape == null || !shape.isUuidLike()) {
            return List.of();
        }

        String compactLower = shape.compactHex();
        String compactUpper = compactLower.toUpperCase(Locale.ROOT);
        String hyphenatedLower = hyphenateUuid(compactLower);
        String hyphenatedUpper = hyphenatedLower.toUpperCase(Locale.ROOT);

        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(compactLower);
        candidates.add(compactUpper);
        candidates.add(hyphenatedLower);
        candidates.add(hyphenatedUpper);
        candidates.add("{" + hyphenatedLower + "}");
        candidates.add("{" + hyphenatedUpper + "}");
        candidates.remove(value);
        return new ArrayList<>(candidates);
    }

    public static List<String> neighborCandidates(String value) {
        IdentifierShape shape = detect(value);
        if (shape == null) {
            return List.of();
        }

        String compact = shape.compactHex();
        Set<String> candidates = new LinkedHashSet<>();
        addFormatted(candidates, shape, incrementTrailingHex(compact, 1));
        addFormatted(candidates, shape, decrementTrailingHex(compact, 1));
        addFormatted(candidates, shape, incrementTrailingHex(compact, 2));
        addFormatted(candidates, shape, replaceTrailingHex(compact, 4, "ffff"));
        candidates.remove(value);
        return new ArrayList<>(candidates);
    }

    public static List<String> truncatedCandidates(String value) {
        IdentifierShape shape = detect(value);
        if (shape == null) {
            return List.of();
        }

        Set<String> candidates = new LinkedHashSet<>();
        String compact = shape.compactHex();
        if (compact.length() >= 8) {
            candidates.add(compact.substring(0, 8));
            candidates.add(compact.substring(compact.length() - 8));
        }

        if (shape.isUuidLike()) {
            candidates.add(formatLikeOriginal(shape, "00000000000000000000000000000000"));
        } else {
            candidates.add("0".repeat(compact.length()));
            if (compact.length() > 8) {
                candidates.add(compact.substring(0, 8) + "0".repeat(compact.length() - 8));
                candidates.add("0".repeat(compact.length() - 8) + compact.substring(compact.length() - 8));
            }
        }

        candidates.remove(value);
        candidates.removeIf(String::isBlank);
        return new ArrayList<>(candidates);
    }

    public static List<String> uuidVersionCandidates(String value) {
        IdentifierShape shape = detect(value);
        if (shape == null || !shape.isUuidLike()) {
            return List.of();
        }

        String compact = shape.compactHex();
        Set<String> candidates = new LinkedHashSet<>();
        for (char version : List.of('1', '3', '4', '5')) {
            String candidate = compact.substring(0, 12) + version + compact.substring(13);
            candidates.add(formatLikeOriginal(shape, candidate));
        }
        candidates.remove(value);
        return new ArrayList<>(candidates);
    }

    private static void addFormatted(Set<String> candidates, IdentifierShape shape, String compactCandidate) {
        if (compactCandidate == null || compactCandidate.isBlank()) {
            return;
        }
        candidates.add(formatLikeOriginal(shape, compactCandidate));
    }

    private static String formatLikeOriginal(IdentifierShape shape, String compactValue) {
        String normalized = shape.prefersUppercase()
            ? compactValue.toUpperCase(Locale.ROOT)
            : compactValue.toLowerCase(Locale.ROOT);
        return switch (shape.kind()) {
            case UUID_HYPHENATED -> hyphenateUuid(normalized);
            case UUID_BRACED -> "{" + hyphenateUuid(normalized) + "}";
            case UUID_COMPACT, HEX_OPAQUE -> normalized;
        };
    }

    private static String hyphenateUuid(String compactUuid) {
        return compactUuid.substring(0, 8)
            + "-" + compactUuid.substring(8, 12)
            + "-" + compactUuid.substring(12, 16)
            + "-" + compactUuid.substring(16, 20)
            + "-" + compactUuid.substring(20);
    }

    private static String incrementTrailingHex(String value, int digits) {
        return adjustTrailingHex(value, digits, 1);
    }

    private static String decrementTrailingHex(String value, int digits) {
        return adjustTrailingHex(value, digits, -1);
    }

    private static String adjustTrailingHex(String value, int digits, int delta) {
        if (value.length() < digits) {
            return null;
        }

        String prefix = value.substring(0, value.length() - digits);
        String suffix = value.substring(value.length() - digits);
        int parsed = Integer.parseInt(suffix, 16);
        int updated = parsed + delta;
        int max = (1 << (digits * 4)) - 1;
        if (updated < 0 || updated > max) {
            return null;
        }
        return prefix + String.format(Locale.ROOT, "%0" + digits + "x", updated);
    }

    private static String replaceTrailingHex(String value, int digits, String replacement) {
        if (value.length() < digits || replacement.length() != digits) {
            return null;
        }
        String candidate = value.substring(0, value.length() - digits) + replacement.toLowerCase(Locale.ROOT);
        return candidate.equals(value) ? null : candidate;
    }

    private static boolean prefersUppercase(String value) {
        return value.chars().anyMatch(Character::isLetter) && value.equals(value.toUpperCase(Locale.ROOT));
    }

    private static String normalizeCase(String value) {
        return value.toLowerCase(Locale.ROOT);
    }

    public enum IdentifierKind {
        UUID_HYPHENATED,
        UUID_BRACED,
        UUID_COMPACT,
        HEX_OPAQUE
    }

    public record IdentifierShape(IdentifierKind kind, String compactHex, boolean prefersUppercase) {

        public boolean isUuidLike() {
            return kind == IdentifierKind.UUID_HYPHENATED
                || kind == IdentifierKind.UUID_BRACED
                || kind == IdentifierKind.UUID_COMPACT;
        }
    }
}
