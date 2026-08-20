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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * UI component that owns the Host port-probe configuration and its dialog.
 * Embeds a "Host Ports..." button; clicking it opens a modeless dialog
 * with an enable checkbox and a custom ports text field.
 */
class HostPortsControl {

    private final JCheckBox enableCheckbox;
    private final JTextField customPortsField;
    private final JButton button;
    private Runnable onChange;

    HostPortsControl() {
        enableCheckbox = new JCheckBox("Enable double-port Host probes", false);
        enableCheckbox.setToolTipText(
            "Add Host parser probes per endpoint using trailing :80 and :443 ports.");

        customPortsField = new JTextField(12);
        customPortsField.setEnabled(false);
        customPortsField.setToolTipText("Comma-separated custom ports, e.g. 4080, 8443");

        enableCheckbox.addActionListener(e -> {
            customPortsField.setEnabled(enableCheckbox.isSelected());
            fireChange();
        });

        button = new JButton("Host Ports...");
        button.setToolTipText("Configure double-port Host header probes and custom ports.");
        button.addActionListener(e -> openDialog());
    }

    JButton button() {
        return button;
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
        button.setEnabled(enabled);
    }

    void setOnChange(Runnable onChange) {
        this.onChange = onChange;
    }

    private void fireChange() {
        if (onChange != null) {
            onChange.run();
        }
    }

    private void openDialog() {
        Window owner = SwingUtilities.getWindowAncestor(button);
        JDialog dialog = new JDialog(owner, "Host port probes", Dialog.ModalityType.MODELESS);
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        content.add(enableCheckbox);
        content.add(Box.createVerticalStrut(8));

        JPanel portsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        portsRow.add(new JLabel("Custom ports (comma-separated):"));
        portsRow.add(customPortsField);
        content.add(portsRow);

        content.add(Box.createVerticalStrut(6));

        JTextArea helpText = new JTextArea(
            "When enabled with no custom ports, two standard lightweight probes are "
            + "generated per endpoint (host:port:80 and host:port:443).\n\n"
            + "Adding a custom port (e.g. 4080) generates three additional probes: "
            + "host:4080, host:4080:80, and host:4080:443.");
        helpText.setEditable(false);
        helpText.setLineWrap(true);
        helpText.setWrapStyleWord(true);
        helpText.setOpaque(false);
        helpText.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));
        helpText.setFont(helpText.getFont().deriveFont(Font.PLAIN, 11f));
        helpText.setForeground(Color.GRAY);
        content.add(helpText);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> {
            fireChange();
            dialog.dispose();
        });
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonRow.add(closeButton);
        content.add(buttonRow);

        dialog.setContentPane(content);
        dialog.setSize(480, 260);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
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
