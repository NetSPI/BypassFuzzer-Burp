package com.bypassfuzzer.burp.ui.dashboard;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JSpinner;
import javax.swing.JTable;
import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

class DashboardPanelTest {

    @Test
    void showsOpenActivitiesAndProvidesPerRowControls() {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        ActivityRegistry registry = new ActivityRegistry();
        MutableActivity activity = new MutableActivity("one", ActivityState.RUNNING);
        AtomicBoolean opened = new AtomicBoolean();
        registry.register(activity, () -> opened.set(true));
        DashboardPanel panel = new DashboardPanel(mock(MontoyaApi.class, RETURNS_DEEP_STUBS), governor, registry);

        try {
            panel.refresh();
            JTable table = find(panel, JTable.class);
            assertEquals(1, table.getRowCount());
            assertEquals("Bypass", table.getValueAt(0, 0));
            assertEquals("Running", table.getValueAt(0, 2));

            clickTableAction(table, 0, 5);
            assertTrue(opened.get());
            clickTableAction(table, 0, 6);
            assertEquals(ActivityState.PAUSED, activity.state);
            panel.refresh();
            assertEquals("Resume", table.getValueAt(0, 6));
            clickTableAction(table, 0, 7);
            assertEquals(ActivityState.STOPPED, activity.state);
        } finally {
            panel.cleanup();
        }
    }

    @Test
    void limitsStartDisabledAtTenAndGlobalPauseIsAnOverlay() {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        ActivityRegistry registry = new ActivityRegistry();
        registry.register(new MutableActivity("one", ActivityState.RUNNING), () -> { });
        DashboardPanel panel = new DashboardPanel(mock(MontoyaApi.class, RETURNS_DEEP_STUBS), governor, registry);

        try {
            JCheckBox enabled = findNamed(panel, "globalLimitsEnabled", JCheckBox.class);
            JSpinner rate = findNamed(panel, "globalMaxRatePerHost", JSpinner.class);
            JSpinner inFlight = findNamed(panel, "globalMaxInFlight", JSpinner.class);
            assertFalse(enabled.isSelected());
            assertEquals(10.0, ((Number) rate.getValue()).doubleValue());
            assertEquals(10, ((Number) inFlight.getValue()).intValue());

            findNamed(panel, "dashboardPauseAll", JButton.class).doClick();
            panel.refresh();
            assertTrue(governor.isPaused());
            assertTrue(find(panel, JTable.class).getValueAt(0, 2).toString().startsWith("Paused globally"));

            registry.entries().get(0).activity().pauseActivity();
            findNamed(panel, "dashboardResumeAll", JButton.class).doClick();
            assertFalse(governor.isPaused());
            assertEquals(ActivityState.PAUSED,
                registry.entries().get(0).activity().activitySnapshot().state());
        } finally {
            panel.cleanup();
        }
    }

    @Test
    void stopAllStopsOnlyActiveActivities() {
        GlobalTrafficGovernor governor = new GlobalTrafficGovernor();
        ActivityRegistry registry = new ActivityRegistry();
        MutableActivity running = new MutableActivity("running", ActivityState.RUNNING);
        MutableActivity idle = new MutableActivity("idle", ActivityState.IDLE);
        registry.register(running, () -> { });
        registry.register(idle, () -> { });
        DashboardPanel panel = new DashboardPanel(mock(MontoyaApi.class, RETURNS_DEEP_STUBS), governor, registry);
        try {
            panel.stopAllActivities();
            assertEquals(ActivityState.STOPPED, running.state);
            assertEquals(ActivityState.IDLE, idle.state);
        } finally {
            panel.cleanup();
        }
    }

    private void clickTableAction(JTable table, int row, int column) {
        assertTrue(table.editCellAt(row, column));
        ((JButton) table.getEditorComponent()).doClick();
    }

    private <T extends Component> T find(Component root, Class<T> type) {
        if (type.isInstance(root)) return type.cast(root);
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                try {
                    return find(child, type);
                } catch (AssertionError ignored) { }
            }
        }
        throw new AssertionError("Missing " + type.getSimpleName());
    }

    private <T extends Component> T findNamed(Component root, String name, Class<T> type) {
        if (type.isInstance(root) && name.equals(root.getName())) return type.cast(root);
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                try {
                    return findNamed(child, name, type);
                } catch (AssertionError ignored) { }
            }
        }
        throw new AssertionError("Missing " + name);
    }

    private static final class MutableActivity implements ManagedActivity {
        private final String id;
        private ActivityState state;

        private MutableActivity(String id, ActivityState state) {
            this.id = id;
            this.state = state;
        }

        @Override public String activityId() { return id; }
        @Override public ActivitySnapshot activitySnapshot() {
            return new ActivitySnapshot(id, "Bypass", "GET https://example.com/one", state, "5 results", 5);
        }
        @Override public void pauseActivity() { state = ActivityState.PAUSED; }
        @Override public void resumeActivity() { state = ActivityState.RUNNING; }
        @Override public void stopActivity() { state = ActivityState.STOPPED; }
    }
}
