package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;

import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.stream.Collectors;

public class RunOptionsPanel extends JPanel {

    private final JCheckBox collaboratorCheckbox;
    private final JCheckBox fuzzExistingCookiesCheckbox;
    private final JTextField requestsPerSecondField;
    private final JTextField throttleStatusCodesField;

    public RunOptionsPanel(FuzzerConfig config, boolean collaboratorAvailable) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Options"));

        JPanel collabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        collaboratorCheckbox = new JCheckBox("Include Collaborator payloads in headers?", config.isEnableCollaboratorPayloads());
        JLabel collabInfoIcon = null;
        if (!collaboratorAvailable) {
            collaboratorCheckbox.setEnabled(false);
            collaboratorCheckbox.setSelected(false);
            collaboratorCheckbox.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");

            collabInfoIcon = new JLabel("ⓘ");
            collabInfoIcon.setForeground(new Color(100, 100, 100));
            collabInfoIcon.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");
            collabInfoIcon.setCursor(new Cursor(Cursor.HAND_CURSOR));
        }
        collabRow.add(collaboratorCheckbox);
        if (collabInfoIcon != null) {
            collabRow.add(collabInfoIcon);
        }
        add(collabRow);

        JPanel fuzzCookiesRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        fuzzExistingCookiesCheckbox = new JCheckBox("Debug Cookies: also fuzz existing cookies in request", config.isEnableFuzzExistingCookies());
        fuzzExistingCookiesCheckbox.setToolTipText("When enabled, tries debug values on cookies already in the request");
        fuzzCookiesRow.add(fuzzExistingCookiesCheckbox);
        add(fuzzCookiesRow);

        JPanel rateRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        rateRow.add(new JLabel("Requests/second (0 = unlimited):"));
        requestsPerSecondField = new JTextField(String.valueOf(config.getRequestsPerSecond()), 5);
        rateRow.add(requestsPerSecondField);
        add(rateRow);

        JPanel throttleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        throttleRow.add(new JLabel("Auto-throttle for status code(s):"));
        throttleStatusCodesField = new JTextField(formatStatusCodes(config.getThrottleStatusCodes()), 10);
        throttleRow.add(throttleStatusCodesField);
        JLabel throttleHelp = new JLabel("(comma-separated, e.g., 429,503)");
        throttleHelp.setFont(throttleHelp.getFont().deriveFont(Font.ITALIC, 11f));
        throttleHelp.setForeground(Color.GRAY);
        throttleRow.add(throttleHelp);
        add(throttleRow);
    }

    public boolean isCollaboratorEnabled() {
        return collaboratorCheckbox.isSelected();
    }

    public void setCollaboratorEnabled(boolean enabled) {
        collaboratorCheckbox.setSelected(enabled);
    }

    public boolean isFuzzExistingCookiesEnabled() {
        return fuzzExistingCookiesCheckbox.isSelected();
    }

    public String requestsPerSecondText() {
        return requestsPerSecondField.getText();
    }

    public String throttleStatusCodesText() {
        return throttleStatusCodesField.getText();
    }

    public void setControlsEnabled(boolean enabled, boolean collaboratorAvailable) {
        fuzzExistingCookiesCheckbox.setEnabled(enabled);
        requestsPerSecondField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);
        collaboratorCheckbox.setEnabled(enabled && collaboratorAvailable);
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
