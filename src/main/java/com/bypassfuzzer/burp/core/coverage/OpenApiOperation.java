package com.bypassfuzzer.burp.core.coverage;

import java.util.Map;

record OpenApiOperation(String method, String url, Map<String, String> headers, String body) {
    OpenApiOperation {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        body = body == null ? "" : body;
    }
}
