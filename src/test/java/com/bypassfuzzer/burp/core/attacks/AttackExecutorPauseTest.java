package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackExecutorPauseTest {

    @Test
    void pausedExecutorWaitsBeforeNextSendAndResumesFromThatRequest() throws Exception {
        CountDownLatch sent = new CountDownLatch(1);
        ExecutionPauseController pause = new ExecutionPauseController();
        AttackExecutor executor = new AttackExecutor(new RequestSender() {
            @Override
            public HttpResponse send(HttpRequest request) {
                sent.countDown();
                return null;
            }

            @Override
            public HttpResponse send(HttpRequest request, long timeout, TimeUnit unit) {
                return send(request);
            }
        });
        executor.enablePauseController(pause);
        pause.pause();

        Thread worker = new Thread(() -> executor.execute(
            "test", "payload", request("/paused", "", "GET", null, ""),
            result -> { }, () -> true, null));
        worker.start();

        assertFalse(sent.await(150, TimeUnit.MILLISECONDS));
        assertTrue(pause.isPaused());

        pause.resume();
        assertTrue(sent.await(2, TimeUnit.SECONDS));
        worker.join(2000);
        assertFalse(worker.isAlive());
    }
}
