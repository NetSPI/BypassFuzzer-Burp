package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
