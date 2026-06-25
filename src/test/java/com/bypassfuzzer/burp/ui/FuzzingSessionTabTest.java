package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.awt.Container;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FuzzingSessionTabTest {

    @Test
    void targetedSessionTabsExcludeGlobalSweepWorkspace() {
        FuzzingSessionTab tab = new FuzzingSessionTab(api(), new FuzzingSessionController(api(), request("/blocked", "", "GET", null, "")));
        JTabbedPane sessionTabs = findTabbedPane(tab);

        assertEquals("Bypass", sessionTabs.getTitleAt(0));
        assertEquals("IDOR", sessionTabs.getTitleAt(1));
        assertEquals("URL Validation", sessionTabs.getTitleAt(2));
    }

    @Test
    void bypassOptionsShowConcurrencyWithoutRequestsPerSecond() {
        FuzzingSessionTab tab = new FuzzingSessionTab(api(), new FuzzingSessionController(api(), request("/blocked", "", "GET", null, "")));
        JTabbedPane sessionTabs = findTabbedPane(tab);

        String uiText = visibleText(sessionTabs.getComponentAt(0));

        assertTrue(uiText.contains("Concurrency:"));
        assertFalse(uiText.contains("Requests/second"));
    }

    private MontoyaApi api() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        return api;
    }

    private JTabbedPane findTabbedPane(JPanel root) {
        for (Component component : root.getComponents()) {
            if (component instanceof JTabbedPane tabs) {
                return tabs;
            }
        }
        throw new AssertionError("No session tabbed pane found");
    }

    private String visibleText(Component root) {
        StringBuilder text = new StringBuilder();
        collectText(root, text);
        return text.toString();
    }

    private void collectText(Component component, StringBuilder text) {
        if (component instanceof javax.swing.JLabel label) {
            text.append(label.getText()).append('\n');
        } else if (component instanceof javax.swing.AbstractButton button) {
            text.append(button.getText()).append('\n');
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectText(child, text);
            }
        }
    }
}
