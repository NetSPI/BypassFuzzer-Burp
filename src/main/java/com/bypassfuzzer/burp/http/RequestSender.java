package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

public interface RequestSender {
    HttpResponse send(HttpRequest request);

    default HttpResponse send(HttpRequest request, BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean() ? send(request) : null;
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode) {
        return send(request);
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean() ? send(request, httpMode) : null;
    }

    HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit);

    default HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit,
                              BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean()
            ? send(request, timeout, timeUnit) : null;
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit) {
        return send(request, timeout, timeUnit);
    }

    default HttpResponse send(HttpRequest request, HttpMode httpMode, long timeout, TimeUnit timeUnit,
                              BooleanSupplier shouldContinue) {
        return shouldContinue == null || shouldContinue.getAsBoolean()
            ? send(request, httpMode, timeout, timeUnit) : null;
    }
}
