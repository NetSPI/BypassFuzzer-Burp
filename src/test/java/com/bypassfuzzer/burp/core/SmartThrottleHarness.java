package com.bypassfuzzer.burp.core;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Standalone test harness for the smart throttle (burst + cooldown) algorithm.
 * Uses java.net.http.HttpClient -- no Burp dependency.
 *
 * <p>Usage: java SmartThrottleHarness &lt;url-or-file&gt; [options]
 * <pre>
 *   --initial-burst 50         Starting burst size for calibration
 *   --initial-cooldown 60      Starting cooldown in seconds
 *   --throttle-codes 429,503   Status codes that indicate throttling
 *   --max-requests 0           Stop after N total requests (0=unlimited)
 *   --min-delay 10             Minimum ms between requests within a burst
 *   --concurrency 10           Number of concurrent requests per wave
 *   --verbose                  Log every request/response
 * </pre>
 *
 * <p>The first argument can be a single URL or a path to a file containing
 * one URL per line.  When a file is provided the harness cycles through
 * all URLs round-robin, which replicates the multi-host traffic pattern
 * that triggers cross-host rate limiting on shared CDN infrastructure.
 */
public class SmartThrottleHarness {

    private static final long INITIAL_SILENT_WAIT_MS = 60_000;
    private static final int CALIBRATION_MAX_REQUESTS = 5000;
    private static final int CLEAN_CYCLES_BEFORE_ADJUST = 5;
    private static final int MAX_RETRY_QUEUE_SIZE = 5000;

    enum Phase { CALIBRATING_BURST, CALIBRATING_COOLDOWN, RUNNING, ADJUSTING }

    // URL pool — rotated round-robin
    private final List<HttpRequest> requestPool;
    private final AtomicInteger poolIndex = new AtomicInteger(0);
    private final String label;

    // Configurable parameters
    private int burstSize;
    private long cooldownMs;
    private final Set<Integer> throttleCodes;
    private final int maxRequests;
    private final long minDelayMs;
    private final int concurrency;
    private final boolean verbose;

    // State
    private Phase phase = Phase.CALIBRATING_BURST;
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private int consecutiveCleanCycles = 0;
    private int previousBurstSize = 0;
    private long previousCooldownMs = 0;
    private final Deque<Integer> retryQueue = new ArrayDeque<>();
    private final Instant startTime = Instant.now();

    private final HttpClient httpClient;
    private final ExecutorService executor;

    public SmartThrottleHarness(List<String> urls, int initialBurst, int initialCooldown,
                                Set<Integer> throttleCodes, int maxRequests,
                                long minDelayMs, int concurrency, boolean verbose) {
        this.burstSize = initialBurst;
        this.cooldownMs = initialCooldown * 1000L;
        this.throttleCodes = throttleCodes;
        this.maxRequests = maxRequests;
        this.minDelayMs = minDelayMs;
        this.concurrency = concurrency;
        this.verbose = verbose;
        this.executor = Executors.newFixedThreadPool(concurrency);
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .executor(executor)
            .build();

        // Build request pool from URLs
        this.requestPool = urls.stream()
            .map(url -> HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build())
            .collect(Collectors.toList());

        // Count distinct hosts for the label
        long hostCount = urls.stream()
            .map(u -> URI.create(u).getHost())
            .distinct()
            .count();
        this.label = String.format("%d URLs across %d hosts", urls.size(), hostCount);
    }

    /** Get the next request from the pool, round-robin. */
    private HttpRequest nextRequest() {
        int idx = poolIndex.getAndIncrement() % requestPool.size();
        return requestPool.get(idx);
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java SmartThrottleHarness <url-or-file> [options]");
            System.err.println("  First arg can be a URL or a file with one URL per line");
            System.err.println("  --initial-burst 50         Starting burst size for calibration");
            System.err.println("  --initial-cooldown 60      Starting cooldown in seconds");
            System.err.println("  --throttle-codes 429,503   Status codes that indicate throttling");
            System.err.println("  --max-requests 0           Stop after N total requests (0=unlimited)");
            System.err.println("  --min-delay 10             Minimum ms between requests within a burst");
            System.err.println("  --concurrency 10           Concurrent requests per wave");
            System.err.println("  --verbose                  Log every request/response");
            System.exit(1);
        }

        String urlOrFile = args[0];
        int initialBurst = 50;
        int initialCooldown = 60;
        Set<Integer> throttleCodes = Set.of(429);
        int maxRequests = 0;
        long minDelay = 10;
        int concurrency = 10;
        boolean verbose = false;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--initial-burst" -> initialBurst = Integer.parseInt(args[++i]);
                case "--initial-cooldown" -> initialCooldown = Integer.parseInt(args[++i]);
                case "--throttle-codes" -> throttleCodes = Stream.of(args[++i].split(","))
                    .map(String::trim).map(Integer::parseInt).collect(Collectors.toSet());
                case "--max-requests" -> maxRequests = Integer.parseInt(args[++i]);
                case "--min-delay" -> minDelay = Long.parseLong(args[++i]);
                case "--concurrency" -> concurrency = Integer.parseInt(args[++i]);
                case "--verbose" -> verbose = true;
                default -> {
                    System.err.println("Unknown option: " + args[i]);
                    System.exit(1);
                }
            }
        }

        // Determine if first arg is a file or a URL
        List<String> urls;
        Path filePath = Path.of(urlOrFile);
        if (Files.isRegularFile(filePath)) {
            try {
                urls = Files.readAllLines(filePath).stream()
                    .map(String::trim)
                    .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .collect(Collectors.toList());
            } catch (IOException e) {
                System.err.println("Failed to read URL file: " + e.getMessage());
                System.exit(1);
                return;
            }
        } else {
            urls = List.of(urlOrFile);
        }

        if (urls.isEmpty()) {
            System.err.println("No URLs provided");
            System.exit(1);
        }

        SmartThrottleHarness harness = new SmartThrottleHarness(
            urls, initialBurst, initialCooldown, throttleCodes, maxRequests, minDelay, concurrency, verbose);
        try {
            harness.run();
        } finally {
            harness.executor.shutdownNow();
        }
    }

    public void run() {
        log("Starting calibration: " + label);
        log("Initial parameters: burst=%d, cooldown=%ds, concurrency=%d, throttle codes=%s",
            burstSize, cooldownMs / 1000, concurrency, throttleCodes);

        try {
            calibrate();
            if (phase == Phase.RUNNING) {
                runBurstLoop();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log("Interrupted.");
        }

        long elapsed = Duration.between(startTime, Instant.now()).toSeconds();
        int total = totalRequests.get();
        double reqPerMin = elapsed > 0 ? (total * 60.0 / elapsed) : total;
        log("Final stats: %d requests in %ds = %.1f req/min effective", total, elapsed, reqPerMin);
    }

    /**
     * Sends a wave of concurrent requests using round-robin URL selection.
     * Returns the status codes received.
     */
    private List<Integer> sendWave(int count) {
        int waveSize = Math.min(count, concurrency);
        List<CompletableFuture<HttpResponse<Void>>> futures = new ArrayList<>(waveSize);

        for (int i = 0; i < waveSize; i++) {
            HttpRequest req = nextRequest();
            futures.add(httpClient.sendAsync(req, HttpResponse.BodyHandlers.discarding()));
        }

        List<Integer> results = new ArrayList<>(waveSize);
        for (var future : futures) {
            try {
                HttpResponse<Void> response = future.join();
                int reqNum = totalRequests.incrementAndGet();
                int status = response.statusCode();
                if (verbose) {
                    String host = response.uri().getHost();
                    log("  [%d] %s -> HTTP %d", reqNum, host, status);
                }
                results.add(status);
            } catch (Exception e) {
                totalRequests.incrementAndGet();
                if (verbose) {
                    log("  Request failed: %s", e.getMessage());
                }
                results.add(-1);
            }
        }
        return results;
    }

    private void calibrate() throws InterruptedException {
        log("Sending calibration burst (concurrency=%d)...", concurrency);
        phase = Phase.CALIBRATING_BURST;
        int successCount = 0;

        while (successCount < CALIBRATION_MAX_REQUESTS && !shouldStop()) {
            int remaining = CALIBRATION_MAX_REQUESTS - successCount;
            List<Integer> results = sendWave(remaining);

            for (int status : results) {
                if (status < 0) continue;

                if (isThrottled(status)) {
                    log("Throttle (%d) at request #%d (%d succeeded before throttle)",
                        status, totalRequests.get(), successCount);

                    log("Waiting silently for reset...");
                    long resetDuration = probeForReset();
                    log("Rate limit reset after %ds", resetDuration / 1000);

                    burstSize = Math.max(1, (int) (successCount * 0.85));
                    cooldownMs = (long) (resetDuration * 1.1);
                    log("Calibrated: burst=%d, cooldown=%ds", burstSize, cooldownMs / 1000);
                    phase = Phase.RUNNING;
                    return;
                }
                successCount++;
            }

            if (minDelayMs > 0) Thread.sleep(minDelayMs);
        }

        // No throttle detected
        log("No rate limit detected after %d requests. Running unlimited.", successCount);
        burstSize = 0;
        cooldownMs = 0;
        phase = Phase.RUNNING;
    }

    private void runBurstLoop() throws InterruptedException {
        int burstNumber = 0;
        while (!shouldStop()) {
            burstNumber++;

            if (burstSize == 0) {
                // Unlimited mode — send waves until throttle detected
                List<Integer> results = sendWave(concurrency);
                for (int status : results) {
                    if (status >= 0 && isThrottled(status)) {
                        log("Throttle detected in unlimited mode, switching to calibration");
                        calibrate();
                        break;
                    }
                }
                if (minDelayMs > 0) Thread.sleep(minDelayMs);
                continue;
            }

            log("=== BURST %d: size %d, cooldown %ds ===", burstNumber, burstSize, cooldownMs / 1000);

            // Drain retry queue first
            int retries = drainRetries();
            int sentInBurst = retries;
            boolean hitThrottle = false;

            while (sentInBurst < burstSize && !shouldStop()) {
                int remaining = burstSize - sentInBurst;
                List<Integer> results = sendWave(remaining);

                for (int status : results) {
                    if (status < 0) continue;
                    sentInBurst++;

                    if (isThrottled(status)) {
                        log("Mid-burst throttle (%d) at request #%d of burst %d",
                            status, sentInBurst, burstNumber);
                        hitThrottle = true;

                        burstSize = Math.max(1, (int) (sentInBurst * 0.85));

                        long resetDuration = probeForReset();
                        if (resetDuration > cooldownMs) {
                            cooldownMs = (long) (resetDuration * 1.1);
                        }
                        log("Adjusted after mid-burst throttle: burst=%d, cooldown=%ds",
                            burstSize, cooldownMs / 1000);
                        consecutiveCleanCycles = 0;
                        break;
                    }
                }
                if (hitThrottle) break;
                if (minDelayMs > 0) Thread.sleep(minDelayMs);
            }

            if (!hitThrottle) {
                log("Burst %d: %d/%d OK", burstNumber, sentInBurst, burstSize);
                consecutiveCleanCycles++;

                if (consecutiveCleanCycles >= CLEAN_CYCLES_BEFORE_ADJUST) {
                    adjust();
                    consecutiveCleanCycles = 0;
                }
            }

            // Cooldown
            if (cooldownMs > 0 && !shouldStop()) {
                log("Cooldown %ds...", cooldownMs / 1000);
                Thread.sleep(cooldownMs);
            }
        }
    }

    private void adjust() throws InterruptedException {
        previousBurstSize = burstSize;
        previousCooldownMs = cooldownMs;

        int newBurst = Math.max(burstSize + 1, (int) (burstSize * 1.1));
        log("Adjustment: trying burst=%d", newBurst);

        boolean hitThrottle = false;
        int sent = 0;
        while (sent < newBurst && !shouldStop()) {
            List<Integer> results = sendWave(newBurst - sent);
            for (int status : results) {
                if (status < 0) continue;
                sent++;
                if (isThrottled(status)) {
                    hitThrottle = true;
                    log("Adjustment: throttle at burst=%d, reverting to %d, adding 5s cooldown",
                        newBurst, previousBurstSize);
                    burstSize = previousBurstSize;
                    cooldownMs = previousCooldownMs + 5000;
                    probeForReset();
                    break;
                }
            }
            if (hitThrottle) break;
            if (minDelayMs > 0) Thread.sleep(minDelayMs);
        }

        if (!hitThrottle) {
            log("Burst OK at %d", newBurst);
            burstSize = newBurst;

            long reducedCooldown = Math.max(1000, (long) (cooldownMs * 0.9));
            log("Adjustment: trying cooldown=%ds", reducedCooldown / 1000);
            cooldownMs = reducedCooldown;
            log("=== RUNNING: burst %d, wait %ds ===", burstSize, cooldownMs / 1000);
        }

        phase = Phase.RUNNING;
    }

    private int drainRetries() throws InterruptedException {
        int count = Math.min(retryQueue.size(), burstSize);
        if (count == 0) return 0;
        log("Retrying %d throttled requests from previous burst", count);

        int retried = 0;
        while (retried < count && !retryQueue.isEmpty()) {
            int waveSize = Math.min(concurrency, count - retried);
            for (int i = 0; i < waveSize && !retryQueue.isEmpty(); i++) {
                retryQueue.poll();
            }
            List<Integer> results = sendWave(waveSize);
            for (int status : results) {
                retried++;
                if (status >= 0 && isThrottled(status) && retryQueue.size() < MAX_RETRY_QUEUE_SIZE) {
                    retryQueue.add(totalRequests.get());
                }
            }
            if (minDelayMs > 0) Thread.sleep(minDelayMs);
        }
        return retried;
    }

    private long probeForReset() throws InterruptedException {
        long start = System.currentTimeMillis();
        long silentWait = cooldownMs > 0 ? cooldownMs : INITIAL_SILENT_WAIT_MS;

        while (!shouldStop()) {
            log("Waiting silently for %ds before probing...", silentWait / 1000);
            Thread.sleep(silentWait);
            // Send a single probe
            int status = sendSingleRequest();
            if (status >= 0 && !isThrottled(status)) {
                return System.currentTimeMillis() - start;
            }
            // Still throttled: double the wait
            silentWait *= 2;
            log("Probe still throttled (%d), doubling wait to %ds", status, silentWait / 1000);
        }
        return System.currentTimeMillis() - start;
    }

    private int sendSingleRequest() {
        try {
            HttpRequest req = nextRequest();
            HttpResponse<Void> response = httpClient.send(req,
                HttpResponse.BodyHandlers.discarding());
            int reqNum = totalRequests.incrementAndGet();
            int status = response.statusCode();
            if (verbose) {
                log("  [%d] %s -> HTTP %d (probe)", reqNum, response.uri().getHost(), status);
            }
            return status;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        } catch (Exception e) {
            if (verbose) {
                log("  Probe failed: %s", e.getMessage());
            }
            return -1;
        }
    }

    private boolean isThrottled(int statusCode) {
        return throttleCodes.contains(statusCode);
    }

    private boolean shouldStop() {
        return Thread.currentThread().isInterrupted()
            || (maxRequests > 0 && totalRequests.get() >= maxRequests);
    }

    private void log(String format, Object... args) {
        long elapsed = Duration.between(startTime, Instant.now()).toSeconds();
        String timestamp = String.format("[%02d:%02d]", elapsed / 60, elapsed % 60);
        String message = args.length == 0 ? format : String.format(format, args);
        System.out.printf("%s %s%n", timestamp, message);
    }
}
