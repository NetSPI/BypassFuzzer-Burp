package com.bypassfuzzer.burp.core.attacks;

public enum AttackType {
    HEADER("header", "Header"),
    PATH("path", "Path"),
    VERB("verb", "Verb"),
    PARAM("param", "Debug Params"),
    COOKIE("cookie", "Debug Cookies"),
    TRAILING_DOT("trailingdot", "Trailing Dot"),
    TRAILING_SLASH("trailingslash", "Trailing Slash"),
    EXTENSION("extension", "Extension"),
    CONTENT_TYPE("contenttype", "Content-Type"),
    ENCODING("encoding", "Encoding"),
    PROTOCOL("protocol", "Protocol"),
    CASE("case", "Case Variation");

    private final String id;
    private final String displayName;

    AttackType(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    public String id() {
        return id;
    }

    public String displayName() {
        return displayName;
    }
}
