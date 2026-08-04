package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManualFilterTest {

    @Test
    void filtersResultsBySignalSubstring() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setSignalContainsFilter("bypass?");
        ManualFilter filter = new ManualFilter(config);

        assertTrue(filter.shouldShow(result("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200")));
        assertFalse(filter.shouldShow(result("LIKELY PUBLIC: authenticated 200 -> unauthenticated 200")));
        assertFalse(filter.shouldShow(result("")));
    }

    @Test
    void filtersResultsBySignalRegex() {
        FilterConfig config = new FilterConfig();
        config.setManualFilterEnabled(true);
        config.setSignalContainsFilter("BYPASS\\?( \\(weak\\))?: .*anonymous (401|403) -> probe 2[0-9][0-9]");
        config.setSignalContainsRegex(true);
        ManualFilter filter = new ManualFilter(config);

        assertTrue(filter.shouldShow(result("BYPASS?: authenticated 200 -> anonymous 403 -> probe 200")));
        assertFalse(filter.shouldShow(result("BYPASS? (weak): authenticated 200 -> anonymous 404 -> probe 200")));
    }

    private AttackResult result(String signal) {
        return new AttackResult("Coverage Sweep", "probe", "target", "family", signal, null, null);
    }
}
