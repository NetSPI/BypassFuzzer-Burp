package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.TimeUnit;

public interface RequestSender {
    HttpResponse send(HttpRequest request);

    default HttpResponse send(HttpRequest request, HttpMode httpMode) {
        return send(request);
    }

    HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit);

    default HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit) {
        return send(request, timeout, timeUnit);
    }
}
