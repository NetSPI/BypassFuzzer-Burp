package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;

import java.util.Set;

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
}
