package com.bypassfuzzer.burp.http;

public record LocatedParameter(String name, String value, ParameterLocation location) {
    public boolean isBody() {
        return location == ParameterLocation.BODY;
    }
}
