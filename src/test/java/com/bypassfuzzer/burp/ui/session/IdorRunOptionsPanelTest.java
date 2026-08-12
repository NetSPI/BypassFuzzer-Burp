package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Set;
import java.util.List;

import javax.swing.JCheckBox;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

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

    @Test
    void collectsPerModeRequestHeaders() throws Exception {
        IdorRunOptionsPanel panel = new IdorRunOptionsPanel(new IdorRunOptions(0, Set.of(429)));
        Field field = IdorRunOptionsPanel.class.getDeclaredField("requestHeadersControl");
        field.setAccessible(true);
        RequestHeadersControl control = (RequestHeadersControl) field.get(panel);
        control.setHeaders(List.of(new ConfiguredHeader("X-Tenant", "blue")));

        assertEquals(List.of(new ConfiguredHeader("X-Tenant", "blue")),
            panel.collect().requestHeaders());
    }
}
