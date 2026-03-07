package com.bypassfuzzer.burp.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.FuzzerEngine;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class FuzzingSessionControllerTest {

    @Test
    void transitionsFromRunningToCompleted() {
        HttpRequest request = mock(HttpRequest.class);
        FakeFuzzerEngine engine = new FakeFuzzerEngine();

        FuzzingSessionController controller = new FuzzingSessionController(request, new FuzzerConfig(), engine);
        List<SessionState> states = new ArrayList<>();
        controller.addStateListener(states::add);

        assertTrue(controller.start());
        engine.complete();

        assertEquals(List.of(SessionState.RUNNING, SessionState.COMPLETED), states);
    }

    @Test
    void stopAndDisposeAreTerminal() {
        HttpRequest request = mock(HttpRequest.class);
        FakeFuzzerEngine engine = new FakeFuzzerEngine();

        FuzzingSessionController controller = new FuzzingSessionController(request, new FuzzerConfig(), engine);
        List<SessionState> states = new ArrayList<>();
        controller.addStateListener(states::add);

        assertTrue(controller.start());
        controller.stop();
        assertTrue(engine.stopCalled);

        engine.complete();
        assertEquals(SessionState.STOPPED, states.get(states.size() - 1));

        controller.dispose();
        controller.dispose();
        assertTrue(engine.cleanupCalled);
        assertEquals(SessionState.DISPOSED, controller.state());
        assertFalse(controller.start());
    }

    private static final class FakeFuzzerEngine extends FuzzerEngine {
        private Runnable completion;
        private boolean running;
        private boolean stopCalled;
        private boolean cleanupCalled;

        private FakeFuzzerEngine() {
            super(null, new FuzzerConfig());
        }

        @Override
        public boolean startFuzzing(HttpRequest request, java.util.function.Consumer<AttackResult> resultCallback, Runnable completionCallback) {
            this.running = true;
            this.completion = completionCallback;
            return true;
        }

        @Override
        public void stopFuzzing() {
            stopCalled = true;
            running = false;
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public void cleanup() {
            cleanupCalled = true;
            running = false;
        }

        private void complete() {
            running = false;
            completion.run();
        }
    }
}
