package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

public class MontoyaRequestSender implements RequestSender {

    private static final AtomicInteger TIMEOUT_THREAD_COUNTER = new AtomicInteger(1);
    private static final ExecutorService TIMEOUT_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "bypassfuzzer-timeout-" + TIMEOUT_THREAD_COUNTER.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    });

    private final MontoyaApi api;
    private final ExecutorService timeoutExecutor;

    public MontoyaRequestSender(MontoyaApi api) {
        this(api, TIMEOUT_EXECUTOR);
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor) {
        this.api = api;
        this.timeoutExecutor = timeoutExecutor;
    }

    @Override
    public HttpResponse send(HttpRequest request) {
        return api.http().sendRequest(request).response();
    }

    @Override
    public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
        Future<HttpResponse> future = null;

        try {
            future = timeoutExecutor.submit(() -> api.http().sendRequest(request).response());
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
        }
    }
}
