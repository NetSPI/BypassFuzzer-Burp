package com.bypassfuzzer.burp.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
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
    void waitBeforeRequestReturnsNegativeWhenInterrupted() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 1, Set.of(429), true);

        assertTrue(rateLimiter.waitBeforeRequest() >= 0);

        Thread.currentThread().interrupt();
        try {
            assertTrue(rateLimiter.waitBeforeRequest() < 0);
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
        assertTrue(rateLimiter.waitBeforeRequest() >= 0);
        long started = System.nanoTime();

        Thread worker = new Thread(() -> assertTrue(rateLimiter.waitBeforeRequest() >= 0));
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
                    if (rateLimiter.waitBeforeRequest() >= 0) {
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

    // Smart throttle tests

    @Test
    void smartThrottleCalibrationSetsBurstAndCooldownViaReportResponse() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);
        assertEquals("Calibrating...", rateLimiter.getSmartThrottleStatus());

        // Simulate 40 successful calibration requests then throttle
        for (int i = 0; i < 40; i++) {
            nanoTime.addAndGet(1_000_000); // advance 1ms
            long epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }

        // Request 41 gets throttled
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        assertTrue(rateLimiter.getSmartThrottleStatus().contains("Waiting for reset"));

        // Simulate 60 seconds passing (initial silent wait), then probe succeeds
        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));

        // Probe request -- silent wait is over
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        // Should now be calibrated: burst = floor(40*0.85) = 34, cooldown = floor(60000*1.1) = 66000
        assertTrue(rateLimiter.getCalibratedBurstSize() > 0);
        assertTrue(rateLimiter.getCalibratedCooldownMs() > 0);
        assertEquals(34, rateLimiter.getCalibratedBurstSize());
        assertEquals(66000, rateLimiter.getCalibratedCooldownMs());
        assertTrue(rateLimiter.getSmartThrottleStatus().contains("Burst 34"));
    }

    @Test
    void smartThrottleBurstGatingGrantsExactlyBurstSizePermits() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);

        // Calibrate: 10 successes then 429
        for (int i = 0; i < 10; i++) {
            nanoTime.addAndGet(1_000_000);
            long epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        // Probe succeeds after 60s (initial silent wait)
        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        int burstSize = rateLimiter.getCalibratedBurstSize();
        assertTrue(burstSize > 0, "Burst size should be > 0 after calibration");
        // burstSize should be floor(10 * 0.85) = 8
        assertEquals(8, burstSize);

        // Should be able to get exactly burstSize permits
        for (int i = 0; i < burstSize; i++) {
            nanoTime.addAndGet(1_000_000);
            epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        // Burst exhausted - burstSent should now equal burstSize
        // The next waitBeforeRequest would block for cooldown
    }

    @Test
    void midBurst429EarlyIncreasesCooldownAndKeepsReasonableBurst() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);

        // Calibrate: 20 successes then 429
        for (int i = 0; i < 20; i++) {
            nanoTime.addAndGet(1_000_000);
            long epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        int calibratedBurst = rateLimiter.getCalibratedBurstSize(); // floor(20*0.85) = 17
        long calibratedCooldown = rateLimiter.getCalibratedCooldownMs(); // floor(60000*1.1) = 66000

        // Send 5 out of 17 (29% < 30%): cooldown problem, not burst problem
        for (int i = 0; i < 5; i++) {
            nanoTime.addAndGet(1_000_000);
            epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        // Burst should be calibratedBurst/2 = 8 (not collapsed to 4)
        int newBurst = rateLimiter.getCalibratedBurstSize();
        assertEquals(8, newBurst, "Early 429 should halve calibrated burst, not collapse to successes*0.85");
        // Cooldown should increase by 50%
        long newCooldown = rateLimiter.getCalibratedCooldownMs();
        assertEquals((long) (calibratedCooldown * 1.5), newCooldown,
            "Early 429 should increase cooldown by 50%");
        assertTrue(rateLimiter.getSmartThrottleStatus().contains("Waiting for reset"));
    }

    @Test
    void midBurst429DeepReducesBurstSize() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);

        // Calibrate: 20 successes then 429
        for (int i = 0; i < 20; i++) {
            nanoTime.addAndGet(1_000_000);
            long epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        int calibratedBurst = rateLimiter.getCalibratedBurstSize(); // floor(20*0.85) = 17

        // Send 12 out of 17 (70% >= 30%): burst problem
        for (int i = 0; i < 12; i++) {
            nanoTime.addAndGet(1_000_000);
            epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        // Burst should shrink based on successes: floor(12*0.85) = 10
        int newBurst = rateLimiter.getCalibratedBurstSize();
        assertTrue(newBurst < calibratedBurst, "Deep 429 should reduce burst");
        assertEquals(10, newBurst, "Deep 429 should use successes*0.85");
        assertTrue(rateLimiter.getSmartThrottleStatus().contains("Waiting for reset"));
    }

    @Test
    void retryQueueDrainsUpToMaxCount() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(429), true);
        rateLimiter.enableSmartThrottle(true);

        HttpRequest mockRequest = mock(HttpRequest.class);
        for (int i = 0; i < 5; i++) {
            rateLimiter.enqueueForRetry(new ThrottledRequest(
                mockRequest, "test", "payload-" + i, "", "", "", 0));
        }

        assertEquals(5, rateLimiter.getRetryQueueSize());

        List<ThrottledRequest> drained = rateLimiter.drainRetryQueue(3);
        assertEquals(3, drained.size());
        assertEquals(2, rateLimiter.getRetryQueueSize());

        List<ThrottledRequest> rest = rateLimiter.drainRetryQueue(10);
        assertEquals(2, rest.size());
        assertEquals(0, rateLimiter.getRetryQueueSize());
    }

    @Test
    void retryQueueBoundedAtMaxSize() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(429), true);
        rateLimiter.enableSmartThrottle(true);

        HttpRequest mockRequest = mock(HttpRequest.class);
        for (int i = 0; i < RateLimiter.MAX_RETRY_QUEUE_SIZE + 100; i++) {
            rateLimiter.enqueueForRetry(new ThrottledRequest(
                mockRequest, "test", "payload-" + i, "", "", "", 0));
        }

        assertEquals(RateLimiter.MAX_RETRY_QUEUE_SIZE, rateLimiter.getRetryQueueSize());
    }

    @Test
    void reThrottledRetriesGoBackInQueue() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(429), true);
        rateLimiter.enableSmartThrottle(true);

        HttpRequest mockRequest = mock(HttpRequest.class);
        ThrottledRequest original = new ThrottledRequest(
            mockRequest, "test", "payload", "", "", "", 0);
        rateLimiter.enqueueForRetry(original);

        List<ThrottledRequest> drained = rateLimiter.drainRetryQueue(1);
        assertEquals(1, drained.size());
        assertEquals(0, rateLimiter.getRetryQueueSize());

        // Simulate re-throttle: put it back with incremented retry count
        ThrottledRequest retried = drained.get(0).withIncrementedRetry();
        rateLimiter.enqueueForRetry(retried);
        assertEquals(1, rateLimiter.getRetryQueueSize());

        List<ThrottledRequest> reDrained = rateLimiter.drainRetryQueue(1);
        assertEquals(1, reDrained.get(0).retryCount());
    }

    @Test
    void cleanCyclesIncrementOnReportCleanBurst() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);

        // Calibrate: 40 successes then 429
        for (int i = 0; i < 40; i++) {
            nanoTime.addAndGet(1_000_000);
            long epoch = rateLimiter.waitBeforeRequest();
            assertTrue(epoch >= 0);
            rateLimiter.reportResponse(200, epoch);
        }
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);
        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        int originalBurst = rateLimiter.getCalibratedBurstSize(); // floor(40*0.85) = 34

        // Report 5 clean bursts
        for (int i = 0; i < 5; i++) {
            rateLimiter.reportCleanBurst();
        }

        // After 5 clean cycles, burst should increase by ~10%
        int newBurst = rateLimiter.getCalibratedBurstSize();
        assertTrue(newBurst > originalBurst,
            "Burst should increase after 5 clean cycles: was " + originalBurst + ", now " + newBurst);
    }

    @Test
    void smartThrottleDisabledProducesIdenticalBehaviorToLegacy() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));

        // Legacy limiter
        RateLimiter legacy = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );

        // Smart throttle limiter with smart throttle disabled
        AtomicLong epochMillis2 = new AtomicLong(10_000);
        AtomicLong nanoTime2 = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter smartDisabled = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis2::get, nanoTime2::get
        );
        // Don't enable smart throttle

        assertFalse(smartDisabled.isSmartThrottleEnabled());

        // Both should have same initial state
        assertEquals(legacy.getCurrentDelayMs(), smartDisabled.getCurrentDelayMs());

        // Report same responses
        legacy.reportResponse(429);
        smartDisabled.reportResponse(429);
        assertEquals(legacy.getCurrentDelayMs(), smartDisabled.getCurrentDelayMs());

        // Recovery
        epochMillis.addAndGet(5_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5_000));
        epochMillis2.addAndGet(5_000);
        nanoTime2.addAndGet(TimeUnit.MILLISECONDS.toNanos(5_000));
        legacy.reportResponse(200);
        smartDisabled.reportResponse(200);
        assertEquals(legacy.getCurrentDelayMs(), smartDisabled.getCurrentDelayMs());
    }

    @Test
    void smartThrottleStatusReportsCorrectPhase() {
        RateLimiter rateLimiter = new RateLimiter(mock(MontoyaApi.class), 0, Set.of(429), true);

        // Before enabling
        assertEquals("Disabled", rateLimiter.getSmartThrottleStatus());

        // After enabling
        rateLimiter.enableSmartThrottle(true);
        assertEquals("Calibrating...", rateLimiter.getSmartThrottleStatus());
    }

    @Test
    void repeatedThrottlingEstablishesFloorThatPreventsOscillation() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );

        // First 429 from 0: adaptiveDelayMs goes 0 -> 1000, no floor (previousAdaptive was 0)
        rateLimiter.reportResponse(429);
        assertEquals(1000, rateLimiter.getCurrentDelayMs());

        // Advance past the backoff adjustment window (1000ms) and send another 429.
        // Now previousAdaptive=1000 > 0, so floor gets set to 2000.
        epochMillis.addAndGet(1001);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(1001));
        rateLimiter.reportResponse(429);
        assertEquals(2000, rateLimiter.getCurrentDelayMs());

        // Recovery: halve repeatedly. Should stop at the floor (2000ms) and not go lower.
        // Recovery window = max(5000, 2000*2) = 5000ms.
        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        // 2000 / 2 = 1000, but floor is 2000, so clamped to 2000 -> no change (reducedDelay >= adaptiveDelayMs).
        // Recovery should be a no-op; delay stays at 2000.
        assertEquals(2000, rateLimiter.getCurrentDelayMs());

        // Even more time passes -- still can't go below floor.
        epochMillis.addAndGet(10_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(10_000));
        rateLimiter.reportResponse(200);
        assertEquals(2000, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void singleTransientThrottleDoesNotSetFloor() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );

        // Single 429 from 0: no floor should be set
        rateLimiter.reportResponse(429);
        assertEquals(1000, rateLimiter.getCurrentDelayMs());

        // Recover fully to 0
        // Recovery window = max(5000, 1000*2) = 5000ms
        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(500, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(250, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(125, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(62, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(31, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(15, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(7, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(3, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        assertEquals(1, rateLimiter.getCurrentDelayMs());

        epochMillis.addAndGet(5000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000));
        rateLimiter.reportResponse(200);
        // 1/2 = 0, and 0 <= baseDelayMs(0), so drops to 0
        assertEquals(0, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void floorRatchetsUpWithConsecutiveThrottling() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );

        // First 429: 0 -> 1000, no floor
        rateLimiter.reportResponse(429);
        assertEquals(1000, rateLimiter.getCurrentDelayMs());

        // Second 429 after guard window: 1000 -> 2000, floor = 2000
        epochMillis.addAndGet(1001);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(1001));
        rateLimiter.reportResponse(429);
        assertEquals(2000, rateLimiter.getCurrentDelayMs());

        // Third 429 after guard window: 2000 -> 4000, floor ratchets to 4000
        epochMillis.addAndGet(2001);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(2001));
        rateLimiter.reportResponse(429);
        assertEquals(4000, rateLimiter.getCurrentDelayMs());

        // Recovery: should stop at 4000 (the floor)
        epochMillis.addAndGet(8000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(8000));
        rateLimiter.reportResponse(200);
        assertEquals(4000, rateLimiter.getCurrentDelayMs());
    }

    @Test
    void isThrottleStatusCodeReflectsConfiguredCodes() {
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, Set.of(429, 503), true);

        assertTrue(rateLimiter.isThrottleStatusCode(429));
        assertTrue(rateLimiter.isThrottleStatusCode(503));
        assertFalse(rateLimiter.isThrottleStatusCode(200));
        assertFalse(rateLimiter.isThrottleStatusCode(404));
    }

    @Test
    void crossThreadEpochFilteringIgnoresStaleResponses() {
        AtomicLong epochMillis = new AtomicLong(10_000);
        AtomicLong nanoTime = new AtomicLong(TimeUnit.MILLISECONDS.toNanos(10_000));
        RateLimiter rateLimiter = new RateLimiter(
            mock(MontoyaApi.class), 0, 0, Set.of(429), true,
            epochMillis::get, nanoTime::get
        );
        rateLimiter.enableSmartThrottle(true);

        // Calibrate: 10 successes then 429
        long lastEpoch = -1;
        for (int i = 0; i < 10; i++) {
            nanoTime.addAndGet(1_000_000);
            lastEpoch = rateLimiter.waitBeforeRequest();
            assertTrue(lastEpoch >= 0);
            rateLimiter.reportResponse(200, lastEpoch);
        }
        nanoTime.addAndGet(1_000_000);
        long epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(429, epoch);

        // Probe succeeds after 60s
        epochMillis.addAndGet(60_000);
        nanoTime.addAndGet(TimeUnit.MILLISECONDS.toNanos(60_000));
        epoch = rateLimiter.waitBeforeRequest();
        assertTrue(epoch >= 0);
        rateLimiter.reportResponse(200, epoch);

        // Now calibrated (burst=8, running). Capture epoch from a new burst.
        long oldEpoch = epoch;
        // Get a new burst permit
        nanoTime.addAndGet(1_000_000);
        long runningEpoch = rateLimiter.waitBeforeRequest();
        assertTrue(runningEpoch >= 0);

        // The old epoch should differ from the running epoch because state transitioned
        // (calibration->probing->running increments smartEpoch).
        // Reporting a 429 with the old epoch should be silently ignored.
        int burstBefore = rateLimiter.getCalibratedBurstSize();
        rateLimiter.reportResponse(429, oldEpoch);
        int burstAfter = rateLimiter.getCalibratedBurstSize();
        assertEquals(burstBefore, burstAfter,
            "Stale epoch response should be ignored and not affect burst size");

        // Report success with the current epoch -- should work normally
        rateLimiter.reportResponse(200, runningEpoch);
    }
}
