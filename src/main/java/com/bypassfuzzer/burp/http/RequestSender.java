package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.TimeUnit;

public interface RequestSender {
    HttpResponse send(HttpRequest request);

    HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit);
}
