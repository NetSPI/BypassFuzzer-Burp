package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import java.awt.Component;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BypassFuzzerTabTest {

    @Test
    void startsWithWelcomeAndSweepTabs() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane tabs = findTabbedPane(tab);

        assertEquals("Welcome", tabs.getTitleAt(0));
        assertEquals("Sweep", tabs.getTitleAt(1));
    }

    @Test
    void welcomeTabUsesFullSizeScrollableLayout() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane tabs = findTabbedPane(tab);
        Component welcome = tabs.getComponentAt(0);

        JScrollPane scrollPane = findScrollPane(welcome);

        assertTrue(scrollPane.getViewport().getView() instanceof JPanel);
        assertFalse(scrollPane.getMaximumSize().width == 800 && scrollPane.getMaximumSize().height == 450);
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
        throw new AssertionError("No top-level tabbed pane found");
    }

    private JScrollPane findScrollPane(Component root) {
        if (root instanceof JScrollPane scrollPane) {
            return scrollPane;
        }
        if (root instanceof java.awt.Container container) {
            for (Component component : container.getComponents()) {
                try {
                    return findScrollPane(component);
                } catch (AssertionError ignored) {
                    // Keep walking the component tree.
                }
            }
        }
        throw new AssertionError("No welcome scroll pane found");
    }
}
