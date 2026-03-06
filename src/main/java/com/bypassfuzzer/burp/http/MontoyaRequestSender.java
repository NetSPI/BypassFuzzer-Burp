package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class MontoyaRequestSender implements RequestSender {

    private final MontoyaApi api;

    public MontoyaRequestSender(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public HttpResponse send(HttpRequest request) {
        return api.http().sendRequest(request).response();
    }

    @Override
    public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<HttpResponse> future = null;

        try {
            future = executor.submit(() -> api.http().sendRequest(request).response());
            return future.get(timeout, timeUnit);
        } catch (TimeoutException e) {
            if (future != null) {
                future.cancel(true);
            }
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            executor.shutdownNow();
            try {
                executor.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
