package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.update.VersionCheckResult;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BypassFuzzerTabTest {

    @Test
    void startsWithDashboardSweepAndTargetedModeTabs() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane tabs = findTabbedPane(tab);

        assertEquals(5, tabs.getTabCount());
        assertEquals("Dashboard", tabs.getTitleAt(0));
        assertEquals("Sweep", tabs.getTitleAt(1));
        assertEquals("Bypass", tabs.getTitleAt(2));
        assertEquals("IDOR", tabs.getTitleAt(3));
        assertEquals("URL Validation", tabs.getTitleAt(4));
    }

    @Test
    void requestSessionIsNestedUnderSelectedMode() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane topLevelTabs = findTabbedPane(tab);

        tab.loadRequest(request("/users/123", "", "GET", null, ""), TargetedMode.IDOR);

        JTabbedPane idorSessions = (JTabbedPane) topLevelTabs.getComponentAt(3);
        assertEquals("IDOR", topLevelTabs.getTitleAt(topLevelTabs.getSelectedIndex()));
        assertEquals(1, idorSessions.getTabCount());
        assertEquals("GET /users/123", idorSessions.getTitleAt(0));
        assertTrue(idorSessions.getComponentAt(0) instanceof FuzzingSessionTab);

        assertEquals(0, ((JTabbedPane) topLevelTabs.getComponentAt(2)).getTabCount());
        assertEquals(0, ((JTabbedPane) topLevelTabs.getComponentAt(4)).getTabCount());
    }

    @Test
    void dashboardStartsWithPerLaunchLimitsDisabled() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JCheckBox enabled = findNamedComponent(tab, "globalLimitsEnabled", JCheckBox.class);
        JButton pauseAll = findNamedComponent(tab, "dashboardPauseAll", JButton.class);
        JButton resumeAll = findNamedComponent(tab, "dashboardResumeAll", JButton.class);

        assertFalse(enabled.isSelected());
        assertTrue(pauseAll.isEnabled());
        assertTrue(resumeAll.isEnabled());
    }

    @Test
    void updateBannerShowsVersionDetailsAndCanBeDismissed() throws Exception {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());

        SwingUtilities.invokeAndWait(() ->
            tab.showUpdateBanner(new VersionCheckResult("1.0.9", "1.0.10", true))
        );
        flushSwingEvents();

        JPanel banner = findNamedComponent(tab, "updateBanner", JPanel.class);
        JLabel message = findNamedComponent(tab, "updateBannerMessage", JLabel.class);
        JButton dismiss = findNamedComponent(tab, "updateBannerDismiss", JButton.class);

        assertTrue(banner.isVisible());
        assertTrue(message.getText().contains("BypassFuzzer 1.0.10 is available"));
        assertTrue(message.getText().contains("running 1.0.9"));
        assertTrue(message.getText().contains("bypassfuzzer.jar"));

        SwingUtilities.invokeAndWait(dismiss::doClick);
        flushSwingEvents();

        assertFalse(banner.isVisible());
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

    private <T extends Component> T findNamedComponent(Component root, String name, Class<T> type) {
        if (type.isInstance(root) && name.equals(root.getName())) {
            return type.cast(root);
        }
        if (root instanceof Container container) {
            for (Component component : container.getComponents()) {
                try {
                    return findNamedComponent(component, name, type);
                } catch (AssertionError ignored) {
                    // Keep walking the component tree.
                }
            }
        }
        throw new AssertionError("No component named " + name + " found");
    }

    private void flushSwingEvents() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }
}
