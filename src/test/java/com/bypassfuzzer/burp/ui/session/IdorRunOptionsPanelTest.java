package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Set;

import javax.swing.JCheckBox;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdorRunOptionsPanelTest {

    @Test
    void autoThrottleDefaultsOnAndCanBeDisabled() throws Exception {
        IdorRunOptionsPanel panel = new IdorRunOptionsPanel(new IdorRunOptions(0, 0, Set.of(429, 503)));
        Field field = IdorRunOptionsPanel.class.getDeclaredField("autoThrottleCheckbox");
        field.setAccessible(true);
        JCheckBox checkbox = (JCheckBox) field.get(panel);

        assertTrue(panel.collect().autoThrottleEnabled());
        checkbox.doClick();

        assertFalse(panel.collect().autoThrottleEnabled());
    }
}
