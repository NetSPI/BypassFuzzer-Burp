package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;

public record CoverageSweepCandidate(
    HttpRequest request,
    HttpResponse originalResponse,
    String dedupeKey,
    String displayUrl,
    String method,
    String host,
    String path,
    int statusCode,
    int contentLength,
    String contentType,
    ZonedDateTime time
) {
}
