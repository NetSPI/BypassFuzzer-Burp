package com.bypassfuzzer.burp.ui;

import com.bypassfuzzer.burp.core.attacks.AttackResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FuzzerResultsTableModelTest {

    @Test
    void assignsImmutableRequestIds() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel();
        AttackResult first = new AttackResult("Header", "one", null, null);
        AttackResult second = new AttackResult("Header", "two", null, null);
        AttackResult third = new AttackResult("Header", "three", null, null);

        model.addResult(first, true);
        model.addResult(second, false);
        model.addResult(third, true);

        assertEquals(1, model.getValueAt(0, 0));
        assertEquals(3, model.getValueAt(1, 0));

        model.applyFilter(result -> true);

        assertEquals(1, model.getValueAt(0, 0));
        assertEquals(2, model.getValueAt(1, 0));
        assertEquals(3, model.getValueAt(2, 0));
    }

    @Test
    void resetsRequestIdsWhenCleared() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel();
        model.addResult(new AttackResult("Header", "one", null, null), true);

        model.clear();
        model.addResult(new AttackResult("Header", "two", null, null), true);

        assertEquals(1, model.getValueAt(0, 0));
    }

    @Test
    void urlValidationLayoutSeparatesMetadataFromPayloadValue() {
        FuzzerResultsTableModel model = new FuzzerResultsTableModel(FuzzerResultsTableModel.TableLayout.URL_VALIDATION);
        model.addResult(new AttackResult(
            "URL Validation",
            "http://127.0.0.1/",
            "{INJECT} (origin header)",
            "CORS",
            "Intruder's",
            null,
            null
        ), true);

        assertEquals("{INJECT} (origin header)", model.getValueAt(0, 1));
        assertEquals("CORS", model.getValueAt(0, 2));
        assertEquals("Intruder's", model.getValueAt(0, 3));
        assertEquals("http://127.0.0.1/", model.getValueAt(0, 4));
    }
}
