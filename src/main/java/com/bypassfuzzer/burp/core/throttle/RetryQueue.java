package com.bypassfuzzer.burp.core.throttle;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * A single bounded FIFO for requests that were throttled and should be retried, replacing the
 * separate ad-hoc retry queues that used to live in the rate limiter, the sweep engine, and the
 * results workspace.
 *
 * @param <T> the queued retry item (e.g. a throttled request plus its presentation context)
 */
public final class RetryQueue<T> {

    /** Upper bound so a pathological run cannot exhaust memory with deferred retries. */
    public static final int DEFAULT_MAX_SIZE = 5000;

    private final ConcurrentLinkedQueue<T> queue = new ConcurrentLinkedQueue<>();
    private final int maxSize;

    public RetryQueue() {
        this(DEFAULT_MAX_SIZE);
    }

    public RetryQueue(int maxSize) {
        this.maxSize = Math.max(1, maxSize);
    }

    /** Adds an item unless the queue is already at its bound (in which case it is dropped). */
    public void enqueue(T item) {
        if (item != null && queue.size() < maxSize) {
            queue.add(item);
        }
    }

    /** Removes and returns up to {@code maxCount} items in FIFO order. */
    public List<T> drain(int maxCount) {
        List<T> drained = new ArrayList<>();
        for (int i = 0; i < maxCount; i++) {
            T item = queue.poll();
            if (item == null) {
                break;
            }
            drained.add(item);
        }
        return drained;
    }

    public int size() {
        return queue.size();
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }
}
