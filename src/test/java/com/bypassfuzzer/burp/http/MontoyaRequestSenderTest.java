package com.bypassfuzzer.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MontoyaRequestSenderTest {

    @Test
    void timedSendReturnsNullWithoutShuttingDownInjectedExecutor() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequest request = mock(HttpRequest.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            when(api.http().sendRequest(request).response()).thenAnswer(invocation -> {
                Thread.sleep(100);
                return mock(HttpResponse.class);
            });

            MontoyaRequestSender sender = new MontoyaRequestSender(api, executor);

            assertNull(sender.send(request, 10, TimeUnit.MILLISECONDS));
            assertFalse(executor.isShutdown());
        } finally {
            executor.shutdownNow();
        }
    }
}
