package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
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
    private final boolean retrySafeRequestsOverHttp1;

    public MontoyaRequestSender(MontoyaApi api) {
        this(api, TIMEOUT_EXECUTOR, false);
    }

    public MontoyaRequestSender(MontoyaApi api, boolean retrySafeRequestsOverHttp1) {
        this(api, TIMEOUT_EXECUTOR, retrySafeRequestsOverHttp1);
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor) {
        this(api, timeoutExecutor, false);
    }

    MontoyaRequestSender(MontoyaApi api, ExecutorService timeoutExecutor, boolean retrySafeRequestsOverHttp1) {
        this.api = api;
        this.timeoutExecutor = timeoutExecutor;
        this.retrySafeRequestsOverHttp1 = retrySafeRequestsOverHttp1;
    }

    @Override
    public HttpResponse send(HttpRequest request) {
        try {
            HttpResponse response = responseFrom(api.http().sendRequest(request));
            if (response != null) {
                return response;
            }

            if (retrySafeRequestsOverHttp1 && isSafeMethod(request)) {
                response = responseFrom(api.http().sendRequest(request, HttpMode.HTTP_1));
                if (response != null) {
                    safeLog("Sweep request returned no response in automatic mode; HTTP/1 retry succeeded: "
                        + requestLabel(request));
                    return response;
                }
            }

            safeLogError("Sweep request returned no response"
                + (retrySafeRequestsOverHttp1 && isSafeMethod(request) ? " after an HTTP/1 retry" : "")
                + ": " + requestLabel(request));
            return null;
        } catch (Exception e) {
            safeLogError("Sweep request failed: " + requestLabel(request) + " - "
                + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return null;
        }
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

    @Override
    public HttpResponse send(HttpRequest request, HttpMode httpMode) {
        try {
            HttpRequestResponse exchange = api.http().sendRequest(request, httpMode);
            HttpResponse response = responseFrom(exchange);
            if (response == null) {
                safeLogError("Request returned no response in " + httpMode + " mode: " + requestLabel(request));
            }
            return response;
        } catch (Exception e) {
            safeLogError("Request failed in " + httpMode + " mode: " + requestLabel(request) + " - "
                + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return null;
        }
    }

    private HttpResponse responseFrom(HttpRequestResponse exchange) {
        return exchange == null ? null : exchange.response();
    }

    private boolean isSafeMethod(HttpRequest request) {
        if (request == null || request.method() == null) {
            return false;
        }
        return "GET".equalsIgnoreCase(request.method()) || "HEAD".equalsIgnoreCase(request.method());
    }

    private String requestLabel(HttpRequest request) {
        if (request == null) {
            return "<null request>";
        }
        try {
            return request.method() + " " + request.url();
        } catch (Exception e) {
            return String.valueOf(request);
        }
    }

    private void safeLog(String message) {
        try {
            api.logging().logToOutput(message);
        } catch (Exception ignored) {
        }
    }

    private void safeLogError(String message) {
        try {
            api.logging().logToError(message);
        } catch (Exception ignored) {
        }
    }
}
