package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.idor.IdorDebugInfoBuilder;
import com.bypassfuzzer.burp.core.idor.IdorEngine;
import com.bypassfuzzer.burp.core.idor.IdorOptions;
import com.bypassfuzzer.burp.core.idor.IdorRequestMutator;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dedicated session tab for IDOR/BOLA analysis.
 */
public class IdorPanel extends JPanel {

    private static final IdorRunOptions DEFAULT_RUN_OPTIONS = new IdorRunOptions(0, java.util.Set.of(429, 503));
    private static final Dimension PLAYBOOK_DIALOG_SIZE = new Dimension(820, 420);
    private static final Dimension DEBUG_DIALOG_SIZE = new Dimension(980, 720);

    private final MontoyaApi api;
    private final HttpRequest originalRequest;
    private final IdorEngine engine;
    private final IdorPlaybookRegistry playbookRegistry = new IdorPlaybookRegistry();
    private final IdorRequestMutator requestMutator = new IdorRequestMutator();
    private final IdorDebugInfoBuilder debugInfoBuilder = new IdorDebugInfoBuilder();

    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private JTextField authorizedIdentifierField;
    private JTextField targetIdentifierField;
    private IdorRunOptionsPanel runOptionsPanel;
    private SessionResultsWorkspace resultsWorkspace;

    private volatile boolean shuttingDown = false;
    private volatile boolean stopRequested = false;

    public IdorPanel(MontoyaApi api, HttpRequest request) {
        super(new BorderLayout());
        this.api = api;
        this.originalRequest = request;
        this.engine = new IdorEngine(api);
        initializeUi();
        applyFilters();
    }

    public void cleanup() {
        shuttingDown = true;
        engine.cleanup();
    }

    private void initializeUi() {
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startButton = new JButton("Start IDOR Analysis");
        startButton.addActionListener(e -> startAnalysis());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopAnalysis());
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        JButton playbooksButton = new JButton("Playbooks");
        playbooksButton.setToolTipText("Open the current IDOR playbook reference.");
        JButton debugButton = new JButton("Debug Info");
        debugButton.setToolTipText("Open IDOR diagnostics and choose whether to copy or save them.");
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(clearButton);
        controlPanel.add(playbooksButton);
        controlPanel.add(debugButton);
        playbooksButton.addActionListener(e -> showPlaybookReference());
        debugButton.addActionListener(e -> showDebugInfoDialog());

        statusLabel = new JLabel("Enter identifier 1 and identifier 2 to compare the authorized control against the unauthorized baseline.");
        warningLabel = new JLabel("");
        warningLabel.setForeground(new Color(204, 102, 0));
        warningLabel.setVisible(false);

        runOptionsPanel = new IdorRunOptionsPanel(DEFAULT_RUN_OPTIONS);

        JPanel topContent = new JPanel();
        topContent.setLayout(new BoxLayout(topContent, BoxLayout.Y_AXIS));

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(controlPanel, BorderLayout.WEST);
        topRow.add(statusLabel, BorderLayout.CENTER);
        topContent.add(topRow);

        JPanel identifierRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        identifierRow.add(new JLabel("Identifier 1 (authorized):"));
        authorizedIdentifierField = new JTextField(18);
        identifierRow.add(authorizedIdentifierField);
        identifierRow.add(new JLabel("Identifier 2 (target):"));
        targetIdentifierField = new JTextField(18);
        identifierRow.add(targetIdentifierField);
        identifierRow.add(new JLabel("Exact literal replacement across the request."));
        topContent.add(identifierRow);

        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(warningLabel);
        topContent.add(warningRow);

        JPanel optionsRow = new JPanel(new BorderLayout());
        optionsRow.add(runOptionsPanel, BorderLayout.WEST);
        topContent.add(optionsRow);

        topPanel.add(topContent, BorderLayout.CENTER);
        return topPanel;
    }

    private void showPlaybookReference() {
        JTextArea summary = new JTextArea(
            "This tab runs IDOR-specific playbooks.\n"
                + "Control and unauthorized baseline requests always run first.\n\n"
                + formatPlaybookSummary()
        );
        summary.setEditable(false);
        summary.setFocusable(false);
        summary.setLineWrap(true);
        summary.setWrapStyleWord(true);
        summary.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(summary);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setPreferredSize(PLAYBOOK_DIALOG_SIZE);

        JOptionPane.showMessageDialog(
            api.userInterface().swingUtils().suiteFrame(),
            scrollPane,
            "Current IDOR Playbooks",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void showDebugInfoDialog() {
        try {
            String authorizedIdentifier = authorizedIdentifierField.getText() == null ? "" : authorizedIdentifierField.getText().trim();
            String targetIdentifier = targetIdentifierField.getText() == null ? "" : targetIdentifierField.getText().trim();
            IdorOptions options = new IdorOptions(authorizedIdentifier, targetIdentifier, runOptionsPanel.collect());
            String debugInfo = debugInfoBuilder.build(originalRequest, options);
            openDebugInfoDialog(debugInfo, authorizedIdentifier, targetIdentifier);
            hideWarning();
        } catch (Exception e) {
            showWarning("Unable to build debug info: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void openDebugInfoDialog(String debugInfo, String authorizedIdentifier, String targetIdentifier) {
        JTextArea debugArea = new JTextArea(debugInfo);
        debugArea.setEditable(false);
        debugArea.setFocusable(true);
        debugArea.setCaretPosition(0);
        debugArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        debugArea.setLineWrap(false);
        debugArea.setWrapStyleWord(false);

        JScrollPane scrollPane = new JScrollPane(debugArea);
        scrollPane.setPreferredSize(DEBUG_DIALOG_SIZE);

        JDialog dialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "IDOR Debug Info", true);
        dialog.setLayout(new BorderLayout());
        dialog.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton copyButton = new JButton("Copy to Clipboard");
        JButton saveButton = new JButton("Save to File");
        JButton closeButton = new JButton("Close");
        buttonPanel.add(copyButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        copyButton.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(debugInfo), null);
            statusLabel.setText("Copied IDOR debug info (" + debugInfo.length() + " chars) to clipboard.");
        });
        saveButton.addActionListener(e -> saveDebugInfoToFile(dialog, debugInfo, authorizedIdentifier, targetIdentifier));
        closeButton.addActionListener(e -> dialog.dispose());

        dialog.pack();
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        dialog.setVisible(true);
    }

    private void saveDebugInfoToFile(JDialog parentDialog,
                                     String debugInfo,
                                     String authorizedIdentifier,
                                     String targetIdentifier) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save IDOR Debug Info");
        chooser.setSelectedFile(new java.io.File(defaultDebugFilename(authorizedIdentifier, targetIdentifier)));

        int result = chooser.showSaveDialog(parentDialog);
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        java.io.File file = chooser.getSelectedFile();
        if (file.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(
                parentDialog,
                "Overwrite existing file?\n" + file.getAbsolutePath(),
                "Confirm Save",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        try {
            Files.writeString(file.toPath(), debugInfo, StandardCharsets.UTF_8);
            statusLabel.setText("Saved IDOR debug info to " + file.getAbsolutePath());
        } catch (Exception e) {
            showWarning("Unable to save debug info: " + e.getMessage());
        }
    }

    private String defaultDebugFilename(String authorizedIdentifier, String targetIdentifier) {
        String authorized = sanitizeFilenamePart(authorizedIdentifier);
        String target = sanitizeFilenamePart(targetIdentifier);
        return "idor-debug-" + authorized + "-to-" + target + ".txt";
    }

    private String sanitizeFilenamePart(String value) {
        if (value == null || value.isBlank()) {
            return "blank";
        }
        return value.replaceAll("[^A-Za-z0-9._-]+", "_");
    }

    private String formatPlaybookSummary() {
        Map<String, List<IdorPlaybook>> grouped = new LinkedHashMap<>();
        grouped.put("Path playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.path."))
            .toList());
        grouped.put("Query playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.query."))
            .toList());
        grouped.put("Body playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.body."))
            .toList());
        grouped.put("Hybrid playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.hybrid."))
            .toList());

        StringBuilder summary = new StringBuilder("Current playbooks:\n\n");
        for (Map.Entry<String, List<IdorPlaybook>> entry : grouped.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }

            summary.append(entry.getKey()).append('\n');
            for (IdorPlaybook playbook : entry.getValue()) {
                summary.append(" - ")
                    .append(playbook.displayName())
                    .append(": ")
                    .append(compactSummary(playbook.id()))
                    .append('\n');
            }
            summary.append('\n');
        }
        summary.append("Add new technique families in core/idor/playbooks/ and register them in IdorPlaybookRegistry.");
        return summary.toString();
    }

    private String compactSummary(String playbookId) {
        return switch (playbookId) {
            case "idor.path.suffix_formats" -> ".json/.html and similar suffix variants";
            case "idor.path.trailing_slash" -> "add or remove the final slash";
            case "idor.path.special_identifier_values" -> "sentinel values like 0, 1, -1, and odd characters";
            case "idor.path.dot_segments" -> "authorized-id/../target-id style dot-segment tricks";
            case "idor.query.conflicting_identifiers" -> "mix target path IDs with conflicting query IDs";
            case "idor.query.parameter_pollution" -> "duplicate identifier params in different orders";
            case "idor.query.comma_separated_identifiers" -> "comma-separated lists like target,authorized";
            case "idor.query.json_wrap" -> "query values wrapped as small JSON objects";
            case "idor.query.identifier_aliases" -> "common alternate param names like id, userId, accountId";
            case "idor.query.numeric_pivots" -> "numeric pivots such as 0, 1, 2, 3, and -1";
            case "idor.body.content_type_tampering" -> "move the ID across urlencoded, JSON, XML, and multipart bodies";
            case "idor.body.json_wrap" -> "wrap JSON IDs as nested objects";
            case "idor.body.deserialization_hints" -> "type-hinted and prototype-like JSON object wrappers";
            case "idor.body.json_batch_identifiers" -> "JSON arrays mixing target and authorized IDs";
            case "idor.body.json_parameter_pollution" -> "repeat JSON identifier keys in both orders";
            case "idor.body.wildcard_identifiers" -> "wildcards such as *, %, _, and .";
            case "idor.body.unexpected_data_types" -> "booleans, nulls, numbers, arrays, and operator-like objects";
            case "idor.hybrid.trailing_control_characters" -> "control bytes, null bytes, and encoded whitespace";
            case "idor.hybrid.empty_identifier_values" -> "empty, blank, null, and undefined values";
            case "idor.hybrid.case_variants" -> "uppercase, lowercase, and alternating-case IDs";
            case "idor.hybrid.canonical_identifier_formats" -> "compact, braced, and canonical UUID forms";
            case "idor.hybrid.uuid_neighbor_edits" -> "small last-byte and last-quartet UUID/hex edits";
            case "idor.hybrid.truncated_identifier_variants" -> "shortened, zero-padded, and all-zero variants";
            case "idor.hybrid.uuid_version_variants" -> "UUID v1/v3/v4/v5-style version swaps";
            case "idor.hybrid.accept_negotiation" -> "representation-specific Accept header variants";
            case "idor.hybrid.cross_source_conflicts" -> "path/query combinations where different sources disagree";
            case "idor.hybrid.identifier_encoding" -> "URL, double-URL, braced, and base64-style encodings";
            case "idor.hybrid.method_override" -> "CRUD methods plus curated method-override headers";
            default -> playbookRegistry.all().stream()
                .filter(playbook -> playbook.id().equals(playbookId))
                .map(IdorPlaybook::description)
                .findFirst()
                .orElse("");
        };
    }

    private JSplitPane buildCenterPanel() {
        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> api.logging().logToOutput(
                "IDOR filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
            ),
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR,
            false
        );
        return resultsWorkspace.component();
    }

    private void startAnalysis() {
        IdorOptions options = collectOptions();
        if (options == null) {
            return;
        }

        if (requestMutator.countOccurrences(originalRequest, options.normalizedAuthorizedIdentifier()) == 0) {
            showWarning("Identifier 1 was not found in the current request.");
            return;
        }

        hideWarning();
        stopRequested = false;
        setControlsEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("IDOR analysis in progress...");

        boolean started = engine.start(originalRequest, options, this::addResult, this::handleCompletion);
        if (!started) {
            updateIdleUi("Unable to start IDOR analysis");
        }
    }

    private void stopAnalysis() {
        stopRequested = true;
        engine.stop();
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        statusLabel.setText("Stopping IDOR analysis...");
    }

    private IdorOptions collectOptions() {
        IdorRunOptions runOptions = runOptionsPanel.collect();

        String authorizedIdentifier = authorizedIdentifierField.getText() == null ? "" : authorizedIdentifierField.getText().trim();
        String targetIdentifier = targetIdentifierField.getText() == null ? "" : targetIdentifierField.getText().trim();

        if (authorizedIdentifier.isEmpty()) {
            showWarning("Enter identifier 1 before starting.");
            return null;
        }

        if (targetIdentifier.isEmpty()) {
            showWarning("Enter identifier 2 before starting.");
            return null;
        }

        if (authorizedIdentifier.equals(targetIdentifier)) {
            showWarning("Identifier 1 and identifier 2 must be different.");
            return null;
        }

        return new IdorOptions(authorizedIdentifier, targetIdentifier, runOptions);
    }

    private void clearResults() {
        resultsWorkspace.clear();
        statusLabel.setText("Results cleared");
    }

    private void applyFilters() {
        resultsWorkspace.applyFilters();
    }

    private void addResult(AttackResult result) {
        SwingUtilities.invokeLater(() -> {
            resultsWorkspace.addResult(result);
            int totalSent = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();
            statusLabel.setText(engine.isRunning()
                ? "IDOR analysis... (" + totalSent + " requests sent, showing " + showing + ")"
                : "Completed: " + totalSent + " requests sent, showing " + showing);
        });
    }

    private void handleCompletion() {
        SwingUtilities.invokeLater(() -> {
            if (shuttingDown) {
                startButton.setEnabled(false);
                stopButton.setEnabled(false);
                return;
            }

            int totalSent = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();
            updateIdleUi((stopRequested ? "Stopped: " : "Completed: ") + totalSent + " requests sent, showing " + showing);
        });
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        setControlsEnabled(true);
    }

    private void setControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        authorizedIdentifierField.setEnabled(enabled);
        targetIdentifierField.setEnabled(enabled);
        runOptionsPanel.setControlsEnabled(enabled);
    }

    private void showWarning(String message) {
        warningLabel.setText(message);
        warningLabel.setVisible(true);
    }

    private void hideWarning() {
        warningLabel.setVisible(false);
    }
}
