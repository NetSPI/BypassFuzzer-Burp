package com.bypassfuzzer.burp.core;

import java.util.function.BooleanSupplier;

/** Cooperative gate that pauses workers between HTTP requests. */
public final class ExecutionPauseController {
    private boolean paused;

    public synchronized void pause() {
        paused = true;
    }

    public synchronized void resume() {
        paused = false;
        notifyAll();
    }

    public synchronized void reset() {
        paused = false;
        notifyAll();
    }

    public synchronized boolean isPaused() {
        return paused;
    }

    public synchronized boolean awaitIfPaused(BooleanSupplier shouldContinue) {
        while (paused && (shouldContinue == null || shouldContinue.getAsBoolean())) {
            try {
                wait();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return !Thread.currentThread().isInterrupted()
            && (shouldContinue == null || shouldContinue.getAsBoolean());
    }
}
