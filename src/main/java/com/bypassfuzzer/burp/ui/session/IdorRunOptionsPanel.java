package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.idor.IdorRunOptions;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * IDOR-specific execution options.
 */
public class IdorRunOptionsPanel extends JPanel {

    private final JTextField requestsPerSecondField;
    private final JTextField throttleStatusCodesField;

    public IdorRunOptionsPanel(IdorRunOptions defaults) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("IDOR Options"));

        JPanel rateRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        rateRow.add(new JLabel("Requests/second (0 = unlimited):"));
        requestsPerSecondField = new JTextField(String.valueOf(defaults.requestsPerSecond()), 5);
        rateRow.add(requestsPerSecondField);
        add(rateRow);

        JPanel throttleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        throttleRow.add(new JLabel("Auto-throttle for status code(s):"));
        throttleStatusCodesField = new JTextField(formatStatusCodes(defaults.throttleStatusCodes()), 10);
        throttleRow.add(throttleStatusCodesField);
        JLabel throttleHelp = new JLabel("(comma-separated, e.g., 429,503)");
        throttleHelp.setFont(throttleHelp.getFont().deriveFont(Font.ITALIC, 11f));
        throttleHelp.setForeground(Color.GRAY);
        throttleRow.add(throttleHelp);
        add(throttleRow);
    }

    public IdorRunOptions collect() {
        int requestsPerSecond;
        try {
            requestsPerSecond = Math.max(0, Integer.parseInt(requestsPerSecondField.getText().trim()));
        } catch (NumberFormatException e) {
            requestsPerSecond = 0;
        }

        return new IdorRunOptions(
            requestsPerSecond,
            SessionInputParsers.parseStatusCodes(throttleStatusCodesField.getText())
        );
    }

    public void setControlsEnabled(boolean enabled) {
        requestsPerSecondField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);
    }

    private String formatStatusCodes(Set<Integer> codes) {
        if (codes == null || codes.isEmpty()) {
            return "429,503";
        }
        return codes.stream()
            .map(String::valueOf)
            .sorted()
            .collect(Collectors.joining(","));
    }
}
