package com.bypassfuzzer.burp.core.coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CoverageSweepSchedulerTest {

    @Test
    void enforcesGlobalAndPerHostConcurrencyIndependently() throws Exception {
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        CoverageSweepOptions options = new CoverageSweepOptions(
            defaults.statuses(), defaults.inScopeOnly(), defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(), 3, 1, defaults.requestsPerSecond(),
            defaults.requestDelayMs(), defaults.throttleStatusCodes(), defaults.mode(),
            defaults.authSelection(), defaults.excludeStaticAssets(),
            defaults.verifyUnauthenticatedAccess(), defaults.doublePortHostProbes(),
            defaults.autoThrottleEnabled(), defaults.requestHeaders(), defaults.payloadSet());
        CoverageSweepScheduler scheduler = new CoverageSweepScheduler(mock(MontoyaApi.class), options);
        HttpResponse response = mock(HttpResponse.class);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        AtomicInteger activeHostA = new AtomicInteger();
        AtomicInteger maxHostA = new AtomicInteger();
        CountDownLatch started = new CountDownLatch(3);
        ExecutorService executor = Executors.newFixedThreadPool(6);
        List<HttpRequest> requests = List.of(
            request("https://a.example.test/1"), request("https://a.example.test/2"),
            request("https://a.example.test/3"), request("https://b.example.test/1"),
            request("https://b.example.test/2"), request("https://c.example.test/1"));

        try {
            List<Runnable> tasks = new ArrayList<>();
            for (HttpRequest request : requests) {
                tasks.add(() -> scheduler.send(request, () -> {
                    int current = active.incrementAndGet();
                    maxActive.accumulateAndGet(current, Math::max);
                    int hostCurrent = request.url().contains("a.example.test")
                        ? activeHostA.incrementAndGet() : 0;
                    maxHostA.accumulateAndGet(hostCurrent, Math::max);
                    started.countDown();
                    try {
                        Thread.sleep(80);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        active.decrementAndGet();
                        if (request.url().contains("a.example.test")) activeHostA.decrementAndGet();
                    }
                    return response;
                }));
            }
            tasks.forEach(executor::submit);
            assertTrue(started.await(2, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
            executor.awaitTermination(2, TimeUnit.SECONDS);
        }

        assertTrue(maxActive.get() <= 3);
        assertTrue(maxHostA.get() <= 1);
    }

    private HttpRequest request(String url) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        return request;
    }
}
