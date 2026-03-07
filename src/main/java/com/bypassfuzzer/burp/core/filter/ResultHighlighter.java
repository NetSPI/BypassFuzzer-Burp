package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import java.awt.Color;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores UI row highlights independently from Swing components.
 */
public class ResultHighlighter {

    private static final Map<String, Color> NAMED_COLORS = new LinkedHashMap<>();

    static {
        NAMED_COLORS.put("Red", new Color(255, 150, 150));
        NAMED_COLORS.put("Orange", new Color(255, 180, 120));
        NAMED_COLORS.put("Yellow", new Color(255, 255, 150));
        NAMED_COLORS.put("Green", new Color(150, 255, 150));
        NAMED_COLORS.put("Blue", new Color(150, 200, 255));
        NAMED_COLORS.put("Cyan", new Color(150, 255, 255));
        NAMED_COLORS.put("Magenta", new Color(255, 150, 255));
        NAMED_COLORS.put("Gray", new Color(200, 200, 200));
    }

    private final Map<AttackResult, Color> highlights = new ConcurrentHashMap<>();

    public Map<String, Color> namedColors() {
        return NAMED_COLORS;
    }

    public void highlight(AttackResult result, Color color) {
        if (result != null && color != null) {
            highlights.put(result, color);
        }
    }

    public void clear(AttackResult result) {
        if (result != null) {
            highlights.remove(result);
        }
    }

    public void clearAll() {
        highlights.clear();
    }

    public Color colorFor(AttackResult result) {
        return highlights.get(result);
    }

    public Color colorFromName(String colorName) {
        return NAMED_COLORS.get(colorName);
    }
}
