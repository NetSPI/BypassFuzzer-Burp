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
}
