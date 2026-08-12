package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.http.ConfiguredHeader;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
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
    private final JTextField requestDelayField;
    private final JTextField throttleStatusCodesField;
    private final JCheckBox autoThrottleCheckbox;
    private final RequestHeadersControl requestHeadersControl;

    public IdorRunOptionsPanel(IdorRunOptions defaults) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("IDOR Options"));

        JPanel rateRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        rateRow.add(new JLabel("Requests/second (0 = unlimited):"));
        requestsPerSecondField = new JTextField(String.valueOf(defaults.requestsPerSecond()), 5);
        rateRow.add(requestsPerSecondField);
        add(rateRow);

        JPanel delayRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        delayRow.add(new JLabel("Delay between requests (ms):"));
        requestDelayField = new JTextField(String.valueOf(defaults.requestDelayMs()), 5);
        delayRow.add(requestDelayField);
        add(delayRow);

        JPanel throttleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        autoThrottleCheckbox = new JCheckBox("Auto throttle", defaults.autoThrottleEnabled());
        autoThrottleCheckbox.setToolTipText(
            "Automatically back off when a configured throttle response is received.");
        throttleRow.add(autoThrottleCheckbox);
        throttleRow.add(new JLabel("Status code(s):"));
        throttleStatusCodesField = new JTextField(formatStatusCodes(defaults.throttleStatusCodes()), 10);
        throttleRow.add(throttleStatusCodesField);
        JLabel throttleHelp = new JLabel("(comma-separated, e.g., 429,503)");
        throttleHelp.setFont(throttleHelp.getFont().deriveFont(Font.ITALIC, 11f));
        throttleHelp.setForeground(Color.GRAY);
        throttleRow.add(throttleHelp);
        add(throttleRow);

        JPanel headersRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        requestHeadersControl = new RequestHeadersControl(this);
        requestHeadersControl.setHeaders(defaults.requestHeaders());
        headersRow.add(requestHeadersControl.button());
        add(headersRow);
    }

    public IdorRunOptions collect() {
        int requestsPerSecond;
        try {
            requestsPerSecond = Math.max(0, Integer.parseInt(requestsPerSecondField.getText().trim()));
        } catch (NumberFormatException e) {
            requestsPerSecond = 0;
        }

        int requestDelayMs;
        try {
            requestDelayMs = Math.max(0, Integer.parseInt(requestDelayField.getText().trim()));
        } catch (NumberFormatException e) {
            requestDelayMs = 0;
        }
        return new IdorRunOptions(
            requestsPerSecond,
            requestDelayMs,
            SessionInputParsers.parseStatusCodes(throttleStatusCodesField.getText()),
            autoThrottleCheckbox.isSelected(),
            requestHeadersControl.headers()
        );
    }

    public void setControlsEnabled(boolean enabled) {
        requestsPerSecondField.setEnabled(enabled);
        requestDelayField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);
        autoThrottleCheckbox.setEnabled(enabled);
        requestHeadersControl.setEnabled(enabled);
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
