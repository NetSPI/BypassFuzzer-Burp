package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class RateLimiterTest {

    @Test
    void waitBeforeRequestReturnsFalseWhenInterrupted() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 1, Set.of(429), true);

        assertTrue(rateLimiter.waitBeforeRequest());

        Thread.currentThread().interrupt();
        try {
            assertFalse(rateLimiter.waitBeforeRequest());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void configuredThrottleCodeBacksOffOnFirstResponse() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(429), true);

        rateLimiter.reportResponse(429);

        assertEquals(1000, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void throttleSlowsAnExistingConfiguredRate() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 1, Set.of(429), true);

        rateLimiter.reportResponse(429);

        assertEquals(2000, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void statusCodeOutsideConfiguredSetDoesNotThrottle() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(503), true);

        rateLimiter.reportResponse(429);

        assertEquals(0, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void fixedDelayAndRateLimitUseTheMoreRestrictiveSpacing() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 20, 125, Set.of(), false);

        assertEquals(125, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void ratesAboveOneThousandDoNotBecomeUnlimited() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 2000, Set.of(), false);

        assertEquals(1, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void fixedDelayPacesConcurrentCallersGlobally() throws Exception {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, 80, Set.of(), false);
        assertTrue(rateLimiter.waitBeforeRequest());
        long started = System.nanoTime();

        Thread worker = new Thread(() -> assertTrue(rateLimiter.waitBeforeRequest()));
        worker.start();
        worker.join(1000);

        assertFalse(worker.isAlive());
        assertTrue((System.nanoTime() - started) / 1_000_000 >= 60);
    }

    @Test
    void simultaneousWorkersReceiveGloballySpacedRequestSlots() throws Exception {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, 40, Set.of(), false);
        CountDownLatch ready = new CountDownLatch(4);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(4);
        List<Long> requestStarts = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < 4; i++) {
            Thread worker = new Thread(() -> {
                ready.countDown();
                try {
                    start.await();
                    if (rateLimiter.waitBeforeRequest()) {
                        requestStarts.add(System.nanoTime());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    finished.countDown();
                }
            });
            worker.start();
        }

        assertTrue(ready.await(1, TimeUnit.SECONDS));
        start.countDown();
        assertTrue(finished.await(2, TimeUnit.SECONDS));
        assertEquals(4, requestStarts.size());
        requestStarts.sort(Long::compareTo);
        long totalSpacingMs = TimeUnit.NANOSECONDS.toMillis(
            requestStarts.get(3) - requestStarts.get(0)
        );
        assertTrue(totalSpacingMs >= 90);
    }

    @Test
    void throttleImmediatelyPushesTheSharedRequestGateForward() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class),
            0,
            0,
            Set.of(429),
            true,
            epochMillis::get,
            nanoTime::get
        );

        rateLimiter.reportResponse(429);

        assertEquals(1000, rateLimiter.getCurrentDelayMs());
        assertEquals(1000, rateLimiter.getRemainingWaitMs());
    }

    @Test
    void successfulResponsesGraduallyRecoverAdaptivePacingAfterQuietWindows() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class),
            0,
            0,
            Set.of(429),
            true,
            epochMillis::get,
            nanoTime::get
        );
        rateLimiter.reportResponse(429);

        epochMillis.addAndGet(4_999);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(4_999));
        rateLimiter.reportResponse(200);
        assertEquals(1000, rateLimiter.getCurrentDelayMs());

        epochMillis.incrementAndGet();
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
        rateLimiter.reportResponse(200);
        assertEquals(500, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5_000));
        rateLimiter.reportResponse(200);
        assertEquals(250, rateLimiter.getCurrentDelayMs());
    }
}
