package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.ConfiguredHeaderParser;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Dimension;
import java.util.List;

/** Per-panel editor for headers that should be included with generated requests. */
final class RequestHeadersControl {

    private final Component parent;
    private final JButton button = new JButton();
    private List<ConfiguredHeader> headers = List.of();

    RequestHeadersControl(Component parent) {
        this.parent = parent;
        button.setToolTipText("Configure headers to send with every request in this mode.");
        button.addActionListener(event -> openEditor());
        updateLabel();
    }

    JButton button() {
        return button;
    }

    List<ConfiguredHeader> headers() {
        return headers;
    }

    void setEnabled(boolean enabled) {
        button.setEnabled(enabled);
    }

    void setHeaders(List<ConfiguredHeader> headers) {
        this.headers = headers == null ? List.of() : List.copyOf(headers);
        updateLabel();
    }

    private void openEditor() {
        JTextArea editor = new JTextArea(ConfiguredHeaderParser.format(headers), 12, 62);
        editor.setLineWrap(false);
        JScrollPane scrollPane = new JScrollPane(editor);
        scrollPane.setPreferredSize(new Dimension(700, 280));
        int result = JOptionPane.showConfirmDialog(
            parent,
            scrollPane,
            "Request Headers - one Name: value per line",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return;
        }
        try {
            setHeaders(ConfiguredHeaderParser.parse(editor.getText()));
        } catch (IllegalArgumentException e) {
            JOptionPane.showMessageDialog(parent, e.getMessage(), "Invalid Request Header",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateLabel() {
        button.setText("Request Headers... (" + headers.size() + ")");
    }
}
