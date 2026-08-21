package com.bypassfuzzer.burp.ui;

/** Targeted testing modes that accept an individual Burp request. */
public enum TargetedMode {
    BYPASS("Bypass"),
    IDOR("IDOR"),
    URL_VALIDATION("URL Validation");

    private final String title;

    TargetedMode(String title) {
        this.title = title;
    }

    public String title() {
        return title;
    }
}
