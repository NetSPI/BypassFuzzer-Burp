package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultHighlighter;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.RowSorter;
import java.awt.Component;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionResultsPanelTest {

    @Test
    void urlValidationTableSortsStringMetadataColumnsWithoutTypeErrors() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.URL_VALIDATION
        );

        panel.addResult(new AttackResult("URL Validation", "payload-1", "target", "family", "Zulu", null, null), true);
        panel.addResult(new AttackResult("URL Validation", "payload-2", "target", "family", "Alpha", null, null), true);

        JTable table = resultsTable(panel);
        RowSorter<?> sorter = table.getRowSorter();

        assertDoesNotThrow(() -> sorter.toggleSortOrder(3));
        assertEquals("Alpha", table.getValueAt(0, 3));
        assertEquals("Zulu", table.getValueAt(1, 3));
    }

    @Test
    void coverageSweepTableLabelsInterestingMarkerAsSignal() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.COVERAGE_SWEEP
        );

        panel.addResult(new AttackResult("Coverage Sweep", "payload", "target", "family", "403 -> 200", null, null), true);

        JTable table = resultsTable(panel);

        assertEquals("Signal", table.getColumnName(3));
        assertEquals("403 -> 200", table.getValueAt(0, 3));
    }


    @Test
    void idorTableSortsStringMetadataColumnsWithoutTypeErrors() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR
        );

        panel.addResult(new AttackResult(
            "IDOR",
            "variant-1",
            "Zulu Group",
            "idor.hybrid.zulu",
            null,
            null,
            null
        ), true);
        panel.addResult(new AttackResult(
            "IDOR",
            "variant-2",
            "Alpha Group",
            "idor.hybrid.alpha",
            null,
            null,
            null
        ), true);

        JTable table = resultsTable(panel);
        RowSorter<?> sorter = table.getRowSorter();

        assertDoesNotThrow(() -> sorter.toggleSortOrder(1));
        assertEquals("Alpha Group", table.getValueAt(0, 1));
        assertEquals("Zulu Group", table.getValueAt(1, 1));
    }

    @Test
    void idorGroupCellUsesBadgeStylingForControlAndBaseline() throws Exception {
        SessionResultsPanel panel = new SessionResultsPanel(
            api(),
            new ResultHighlighter(),
            () -> { },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR
        );

        panel.addResult(new AttackResult("IDOR", "control", "Control", "idor.baseline.control", null, null, null), true);
        panel.addResult(new AttackResult("IDOR", "baseline", "Baseline", "idor.baseline.target", null, null, null), true);

        JTable table = resultsTable(panel);
        Component controlCell = table.prepareRenderer(table.getCellRenderer(0, 1), 0, 1);
        Component baselineCell = table.prepareRenderer(table.getCellRenderer(1, 1), 1, 1);

        assertNotEquals(table.getBackground(), controlCell.getBackground());
        assertNotEquals(table.getBackground(), baselineCell.getBackground());
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

    private JTable resultsTable(SessionResultsPanel panel) throws Exception {
        Field field = SessionResultsPanel.class.getDeclaredField("resultsTable");
        field.setAccessible(true);
        return (JTable) field.get(panel);
    }
}
