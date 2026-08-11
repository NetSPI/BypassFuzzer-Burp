package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RunOptionsPanelTest {

    @Test
    void collaboratorHeaderPayloadsAreSelectedByDefaultWhenAvailable() {
        RunOptionsPanel panel = new RunOptionsPanel(new FuzzerConfig(), true);

        assertTrue(panel.isCollaboratorEnabled());
    }

    @Test
    void collaboratorHeaderPayloadsRemainDisabledWhenUnavailable() {
        RunOptionsPanel panel = new RunOptionsPanel(new FuzzerConfig(), false);

        assertFalse(panel.isCollaboratorEnabled());
    }
}
