package com.bypassfuzzer.burp.core.throttle;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalTrafficGovernorTest {

    @Test
    void smoothsAdmissionsForTheSameHost() {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        governor.configure(true, 10, 40.0);
        HttpRequest request = request("/limited", "", "GET", null, "");
        List<Long> admissions = new ArrayList<>();

        for (int index = 0; index < 3; index++) {
            governor.execute(request, () -> {
                admissions.add(System.nanoTime());
                return true;
            }, () -> true);
        }

        assertEquals(3, admissions.size());
        for (int index = 1; index < admissions.size(); index++) {
            long gapMillis = TimeUnit.NANOSECONDS.toMillis(admissions.get(index) - admissions.get(index - 1));
            assertTrue(gapMillis >= 18, "Expected smooth pacing, observed " + gapMillis + " ms");
        }
    }

    @Test
    void capsTotalConcurrentPhysicalRequests() throws Exception {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        governor.configure(true, 2, 10_000.0);
        HttpRequest request = request("/slow", "", "GET", null, "");
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maximum = new AtomicInteger();
        CountDownLatch started = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(6);

        try {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int index = 0; index < 6; index++) {
                futures.add(pool.submit(() -> governor.execute(request, () -> {
                    int current = active.incrementAndGet();
                    maximum.accumulateAndGet(current, Math::max);
                    started.countDown();
                    try {
                        release.await(2, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        active.decrementAndGet();
                    }
                    return true;
                }, () -> true)));
            }

            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertEquals(2, maximum.get());
            assertEquals(2, governor.snapshot().inFlight());
            release.countDown();
            for (Future<Boolean> future : futures) assertTrue(future.get(3, TimeUnit.SECONDS));
            assertEquals(0, governor.snapshot().inFlight());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void pacesDifferentHostsIndependently() {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        governor.configure(true, 10, 4.0);
        HttpRequest firstHost = mock(HttpRequest.class);
        HttpRequest secondHost = mock(HttpRequest.class);
        when(firstHost.url()).thenReturn("https://one.example/a");
        when(secondHost.url()).thenReturn("https://two.example/b");
        List<Long> admissions = new ArrayList<>();

        governor.execute(firstHost, () -> { admissions.add(System.nanoTime()); return true; }, () -> true);
        governor.execute(secondHost, () -> { admissions.add(System.nanoTime()); return true; }, () -> true);
        governor.execute(firstHost, () -> { admissions.add(System.nanoTime()); return true; }, () -> true);

        long crossHostGap = TimeUnit.NANOSECONDS.toMillis(admissions.get(1) - admissions.get(0));
        long sameHostGap = TimeUnit.NANOSECONDS.toMillis(admissions.get(2) - admissions.get(0));
        assertTrue(crossHostGap < 100, "Different hosts should not share a rate schedule");
        assertTrue(sameHostGap >= 220, "Same host should retain its 250 ms schedule");
    }

    @Test
    void globalPauseBlocksAndCancellationPreventsALateSend() throws Exception {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        governor.pause();
        AtomicBoolean continueScan = new AtomicBoolean(true);
        AtomicBoolean sent = new AtomicBoolean(false);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        try {
            Future<Boolean> result = pool.submit(() -> governor.execute(
                request("/paused", "", "GET", null, ""),
                () -> {
                    sent.set(true);
                    return true;
                },
                continueScan::get));
            waitForQueued(governor);
            assertFalse(result.isDone());

            continueScan.set(false);
            assertNull(result.get(2, TimeUnit.SECONDS));
            assertFalse(sent.get());
            assertTrue(governor.isPaused());
        } finally {
            governor.resume();
            pool.shutdownNow();
        }
    }

    private void waitForQueued(GlobalTrafficGovernor governor) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (governor.snapshot().queued() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertEquals(1, governor.snapshot().queued());
    }
}
