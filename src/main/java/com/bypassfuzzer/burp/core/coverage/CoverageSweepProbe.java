package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.requests.HttpRequest;

public record CoverageSweepProbe(
    String label,
    String family,
    HttpRequest request
) {
}
