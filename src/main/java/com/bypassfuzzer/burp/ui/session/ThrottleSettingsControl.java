package com.bypassfuzzer.burp.ui.session;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Dialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared component that owns all throttle-related fields and the dialog.
 * Each tool embeds {@link #button()} in its options panel. Clicking the
 * button opens a modeless dialog with the appropriate subset of controls.
 */
public class ThrottleSettingsControl {

    private final JTextField concurrencyField;        // null if not shown
    private final JTextField perHostConcurrencyField;  // null if not shown
    private final JTextField requestsPerSecondField;   // null if not shown
    private final JTextField requestDelayField;
    private final JTextField throttleStatusCodesField;
    private final JCheckBox autoThrottleCheckbox;
    private final JCheckBox smartThrottleCheckbox;
    private final JButton throttleButton;
    private final String concurrencyLabel;

    public ThrottleSettingsControl(ThrottleDefaults defaults) {
        this.concurrencyLabel = defaults.concurrencyLabel();

        concurrencyField = defaults.concurrency() >= 0
            ? new JTextField(String.valueOf(defaults.concurrency()), 5) : null;
        perHostConcurrencyField = defaults.perHostConcurrency() >= 0
            ? new JTextField(String.valueOf(defaults.perHostConcurrency()), 4) : null;
        requestsPerSecondField = defaults.requestsPerSecond() >= 0
            ? new JTextField(String.valueOf(defaults.requestsPerSecond()), 5) : null;
        requestDelayField = new JTextField(String.valueOf(defaults.requestDelayMs()), 6);
        throttleStatusCodesField = new JTextField(formatStatusCodes(defaults.throttleStatusCodes()), 10);
        autoThrottleCheckbox = new JCheckBox("Auto throttle", defaults.autoThrottle());
        autoThrottleCheckbox.setToolTipText(
            "Automatically back off when a configured throttle response is received.");
        smartThrottleCheckbox = new JCheckBox("Smart throttle (burst + cooldown)", defaults.smartThrottle());
        smartThrottleCheckbox.setToolTipText(
            "Auto-calibrates burst size and cooldown duration by observing throttle responses. "
            + "Sends fast bursts then waits, maximizing throughput against rate-limited targets.");
        smartThrottleCheckbox.addActionListener(e -> updateSmartThrottleFieldState());
        updateSmartThrottleFieldState();

        throttleButton = new JButton("Throttle...");
        throttleButton.setToolTipText("Configure concurrency, delay, and throttle response handling.");
        throttleButton.addActionListener(e -> openThrottleDialog());
    }

    /** Returns the "Throttle..." button for embedding in host panel. */
    public JButton button() {
        return throttleButton;
    }

    public int concurrency() {
        return concurrencyField != null ? parsePositiveInt(concurrencyField, 1) : 1;
    }

    public int perHostConcurrency() {
        return perHostConcurrencyField != null ? parsePositiveInt(perHostConcurrencyField, 1) : 1;
    }

    public int requestsPerSecond() {
        return requestsPerSecondField != null ? parseNonNegativeInt(requestsPerSecondField, 0) : 0;
    }

    public int requestDelayMs() {
        return parseNonNegativeInt(requestDelayField, 0);
    }

    public Set<Integer> throttleStatusCodes() {
        return SessionInputParsers.parseStatusCodes(throttleStatusCodesField.getText());
    }

    public String throttleStatusCodesText() {
        return throttleStatusCodesField.getText();
    }

    public boolean isAutoThrottleEnabled() {
        return autoThrottleCheckbox.isSelected();
    }

    public boolean isSmartThrottleEnabled() {
        return smartThrottleCheckbox.isSelected();
    }

    public void setEnabled(boolean enabled) {
        if (requestsPerSecondField != null) requestsPerSecondField.setEnabled(enabled);
        requestDelayField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);
        autoThrottleCheckbox.setEnabled(enabled);
        smartThrottleCheckbox.setEnabled(enabled);
        throttleButton.setEnabled(enabled);
        if (enabled) {
            updateSmartThrottleFieldState();
        } else {
            if (concurrencyField != null) concurrencyField.setEnabled(false);
            if (perHostConcurrencyField != null) perHostConcurrencyField.setEnabled(false);
        }
    }

    private void openThrottleDialog() {
        Window owner = SwingUtilities.getWindowAncestor(throttleButton);
        JDialog dialog = new JDialog(owner, "Throttle settings", Dialog.ModalityType.MODELESS);
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        if (concurrencyField != null) {
            JPanel concurrencyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            concurrencyRow.add(new JLabel(concurrencyLabel + ":"));
            concurrencyRow.add(concurrencyField);
            if (perHostConcurrencyField != null) {
                concurrencyRow.add(new JLabel("Per-host:"));
                concurrencyRow.add(perHostConcurrencyField);
            } else {
                JLabel concurrencyHelp = new JLabel("(parallel attack families)");
                concurrencyHelp.setFont(concurrencyHelp.getFont().deriveFont(Font.ITALIC, 11f));
                concurrencyHelp.setForeground(Color.GRAY);
                concurrencyRow.add(concurrencyHelp);
            }
            content.add(concurrencyRow);
        }

        if (requestsPerSecondField != null) {
            JPanel rpsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            rpsRow.add(new JLabel("Requests/second (0 = unlimited):"));
            rpsRow.add(requestsPerSecondField);
            content.add(rpsRow);
        }

        JPanel delayRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        delayRow.add(new JLabel("Delay between requests (ms):"));
        delayRow.add(requestDelayField);
        JLabel delayHelp = new JLabel("(global minimum; 0 = none)");
        delayHelp.setFont(delayHelp.getFont().deriveFont(Font.ITALIC, 11f));
        delayHelp.setForeground(Color.GRAY);
        delayRow.add(delayHelp);
        content.add(delayRow);

        content.add(Box.createVerticalStrut(6));

        content.add(autoThrottleCheckbox);

        JPanel codesRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        codesRow.add(new JLabel("Throttle response codes:"));
        codesRow.add(throttleStatusCodesField);
        JLabel codesHelp = new JLabel("(comma-separated, e.g., 429,503)");
        codesHelp.setFont(codesHelp.getFont().deriveFont(Font.ITALIC, 11f));
        codesHelp.setForeground(Color.GRAY);
        codesRow.add(codesHelp);
        content.add(codesRow);

        content.add(Box.createVerticalStrut(6));
        content.add(smartThrottleCheckbox);

        JTextArea smartExplanation = new JTextArea(
            "When enabled, smart throttle auto-manages concurrency and delay. "
            + "It sends fast bursts then waits, auto-calibrating to maximize throughput.");
        smartExplanation.setEditable(false);
        smartExplanation.setLineWrap(true);
        smartExplanation.setWrapStyleWord(true);
        smartExplanation.setOpaque(false);
        smartExplanation.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));
        content.add(smartExplanation);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(closeButton);
        content.add(buttonRow);

        dialog.setContentPane(content);
        dialog.setSize(560, 340);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private void updateSmartThrottleFieldState() {
        boolean smart = smartThrottleCheckbox.isSelected();
        if (concurrencyField != null) concurrencyField.setEnabled(!smart);
        if (perHostConcurrencyField != null) perHostConcurrencyField.setEnabled(!smart);
        requestDelayField.setEnabled(!smart);
    }

    private static String formatStatusCodes(Set<Integer> codes) {
        if (codes == null || codes.isEmpty()) {
            return "429,503";
        }
        return codes.stream()
            .sorted()
            .map(String::valueOf)
            .collect(Collectors.joining(","));
    }

    private static int parsePositiveInt(JTextField field, int fallback) {
        try {
            return Math.max(1, Integer.parseInt(field.getText().trim()));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static int parseNonNegativeInt(JTextField field, int fallback) {
        try {
            return Math.max(0, Integer.parseInt(field.getText().trim()));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
