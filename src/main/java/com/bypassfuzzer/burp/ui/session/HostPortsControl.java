package com.bypassfuzzer.burp.ui.session;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.FlowLayout;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Inline Host Parsing options embedded in the Sweep Payload Families dialog.
 */
class HostPortsControl {

    private final JCheckBox enableCheckbox;
    private final JTextField customPortsField;
    private Runnable onChange;

    HostPortsControl() {
        enableCheckbox = new JCheckBox("Enable double-port Host probes", true);
        enableCheckbox.setToolTipText(
            "Add Host parser probes per endpoint using trailing :80 and :443 ports.");

        customPortsField = new JTextField(12);
        customPortsField.setEnabled(true);
        customPortsField.setToolTipText("Comma-separated custom ports, e.g. 4080, 8443");

        enableCheckbox.addActionListener(e -> {
            customPortsField.setEnabled(enableCheckbox.isSelected());
            fireChange();
        });
        customPortsField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { fireChange(); }
            @Override public void removeUpdate(DocumentEvent event) { fireChange(); }
            @Override public void changedUpdate(DocumentEvent event) { fireChange(); }
        });
    }

    /**
     * Returns the list of custom ports when enabled, or an empty list when disabled.
     * A list containing only {@code 0} signals "enabled with no custom ports" — the
     * generator treats port-0 entries as a no-op for custom probes but still produces
     * the standard lightweight probes.
     */
    List<Integer> ports() {
        if (!enableCheckbox.isSelected()) {
            return List.of();
        }
        List<Integer> custom = parsePorts(customPortsField.getText());
        return custom.isEmpty() ? List.of(0) : custom;
    }

    int probeCount() {
        if (!enableCheckbox.isSelected()) {
            return 0;
        }
        List<Integer> customPorts = parsePorts(customPortsField.getText());
        return customPorts.size() * 3 + 2;
    }

    void setEnabled(boolean enabled) {
        enableCheckbox.setEnabled(enabled);
        customPortsField.setEnabled(enabled && enableCheckbox.isSelected());
    }

    void setOnChange(Runnable onChange) {
        this.onChange = onChange;
    }

    private void fireChange() {
        if (onChange != null) {
            onChange.run();
        }
    }

    JPanel configurationPanel() {
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createTitledBorder("Host Parsing: double-port probes"));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        JPanel enabledRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        enabledRow.add(enableCheckbox);
        content.add(enabledRow);
        JPanel portsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        portsRow.add(new JLabel("Custom ports (comma-separated):"));
        portsRow.add(customPortsField);
        content.add(portsRow);
        JLabel help = new JLabel(
            "Default probes: host:port:80 and host:port:443. Custom ports add three variants each.");
        help.setBorder(BorderFactory.createEmptyBorder(2, 8, 4, 4));
        content.add(help);
        return content;
    }

    private static List<Integer> parsePorts(String input) {
        if (input == null || input.trim().isEmpty()) {
            return List.of();
        }
        return Arrays.stream(input.split(","))
            .map(String::trim)
            .filter(token -> !token.isEmpty())
            .map(token -> {
                try {
                    int port = Integer.parseInt(token);
                    return port >= 1 && port <= 65535 ? port : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            })
            .filter(Objects::nonNull)
            .distinct()
            .collect(Collectors.toList());
    }
}
