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
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
