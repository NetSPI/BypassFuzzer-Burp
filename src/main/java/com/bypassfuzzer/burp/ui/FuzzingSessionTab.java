package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.http.RequestPathUtils;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.session.SessionPreflightAnalyzer;
import com.bypassfuzzer.burp.session.SessionRunOptions;
import com.bypassfuzzer.burp.session.SessionState;
import com.bypassfuzzer.burp.ui.session.AttackSelectionPanel;
import com.bypassfuzzer.burp.ui.session.IdorPanel;
import com.bypassfuzzer.burp.ui.session.RunOptionsPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsWorkspace;
import com.bypassfuzzer.burp.ui.session.SessionRunOptionsSupport;
import com.bypassfuzzer.burp.ui.session.UrlValidationPanel;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;

/**
 * Individual fuzzing session tab.
 */
public class FuzzingSessionTab extends JPanel {

    private final MontoyaApi api;
    private final FuzzingSessionController sessionController;
    private final FuzzerConfig config;
    private final HttpRequest request;
    private final String tabTitle;
    private final SessionPreflightAnalyzer preflightAnalyzer = new SessionPreflightAnalyzer();

    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private AttackSelectionPanel attackSelectionPanel;
    private RunOptionsPanel runOptionsPanel;
    private SessionResultsWorkspace resultsWorkspace;
    private UrlValidationPanel urlValidationPanel;
    private IdorPanel idorPanel;

    private volatile boolean shuttingDown = false;

    public FuzzingSessionTab(MontoyaApi api, FuzzingSessionController sessionController) {
        this.api = api;
        this.sessionController = sessionController;
        this.request = sessionController.request();
        this.config = sessionController.config();
        this.tabTitle = request.method() + " " + truncate(RequestPathUtils.extractPath(request.url()), 30);

        sessionController.addResultListener(this::addResult);
        sessionController.addStateListener(this::handleSessionStateChange);

        initializeUi();
        applyFilters();
    }

    public String getTabTitle() {
        return tabTitle;
    }

    public String getSessionId() {
        return sessionController.sessionId();
    }

    public void stopFuzzing() {
        sessionController.stop();
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        statusLabel.setText("Stopping...");
    }

    public void cleanup() {
        shuttingDown = true;
        sessionController.dispose();
        if (urlValidationPanel != null) {
            urlValidationPanel.cleanup();
        }
        if (idorPanel != null) {
            idorPanel.cleanup();
        }
    }

    private void initializeUi() {
        setLayout(new BorderLayout());
        add(buildSessionTabs(), BorderLayout.CENTER);

        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(new JLabel(String.format("Target: %s %s", request.method(), request.url())));
        add(infoPanel, BorderLayout.SOUTH);
    }

    private JTabbedPane buildSessionTabs() {
        JTabbedPane sessionTabs = new JTabbedPane();
        sessionTabs.addTab("Bypass", buildBypassTab());
        idorPanel = new IdorPanel(api, request);
        sessionTabs.addTab("IDOR", idorPanel);
        urlValidationPanel = new UrlValidationPanel(api, request);
        sessionTabs.addTab("URL Validation", urlValidationPanel);
        return sessionTabs;
    }

    private JPanel buildBypassTab() {
        JPanel bypassPanel = new JPanel(new BorderLayout());
        bypassPanel.add(buildTopPanel(), BorderLayout.NORTH);
        bypassPanel.add(buildCenterPanel(), BorderLayout.CENTER);
        return bypassPanel;
    }

    private JPanel buildTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startButton = new JButton("Start Fuzzing");
        startButton.addActionListener(e -> startFuzzing());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopFuzzing());
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(clearButton);

        statusLabel = new JLabel("Ready. Target: " + request.method() + " " + request.url());
        warningLabel = new JLabel("");
        warningLabel.setForeground(new java.awt.Color(204, 102, 0));
        warningLabel.setVisible(false);

        attackSelectionPanel = new AttackSelectionPanel(config, () -> warningLabel.setVisible(false));
        runOptionsPanel = new RunOptionsPanel(config, isCollaboratorAvailable());

        JPanel topContent = new JPanel();
        topContent.setLayout(new BoxLayout(topContent, BoxLayout.Y_AXIS));

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(controlPanel, BorderLayout.WEST);
        topRow.add(statusLabel, BorderLayout.CENTER);
        topContent.add(topRow);

        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(warningLabel);
        topContent.add(warningRow);

        JPanel optionsRow = new JPanel(new BorderLayout());
        optionsRow.add(attackSelectionPanel, BorderLayout.CENTER);
        optionsRow.add(runOptionsPanel, BorderLayout.EAST);
        topContent.add(optionsRow);

        topPanel.add(topContent, BorderLayout.CENTER);
        return topPanel;
    }

    private JSplitPane buildCenterPanel() {
        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> api.logging().logToOutput(
                "Filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
            ),
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.DEFAULT,
            false
        );
        return resultsWorkspace.component();
    }

    private void startFuzzing() {
        SessionRunOptions runOptions = collectRunOptions();
        if (!runOptions.hasEnabledAttacks()) {
            warningLabel.setText("Please select at least one attack type before starting.");
            warningLabel.setVisible(true);
            return;
        }

        if (runOptions.collaboratorPayloads() && !isCollaboratorAvailable()) {
            int choice = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "Burp Collaborator is not available.\n\nContinue fuzzing without Collaborator payloads?",
                "Collaborator Not Available",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );

            if (choice != JOptionPane.YES_OPTION) {
                return;
            }

            runOptionsPanel.setCollaboratorEnabled(false);
            runOptions = runOptions.withoutCollaboratorPayloads();
        }

        runOptions.applyTo(config);
        warningLabel.setVisible(false);
        setAttackControlsEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Fuzzing in progress...");

        List<String> warnings = preflightAnalyzer.analyze(request, runOptions);
        if (!warnings.isEmpty()) {
            warningLabel.setText("Note: " + String.join("; ", warnings));
            warningLabel.setVisible(true);
        }

        if (!sessionController.start()) {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            setAttackControlsEnabled(true);
            statusLabel.setText("Unable to start fuzzing");
        }
    }

    private SessionRunOptions collectRunOptions() {
        return SessionRunOptionsSupport.collect(attackSelectionPanel, runOptionsPanel);
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
            try {
                resultsWorkspace.addResult(result);

                int totalSent = resultsWorkspace.allResultsCount();
                int showing = resultsWorkspace.shownResultsCount();
                statusLabel.setText(sessionController.isRunning()
                    ? "Fuzzing... (" + totalSent + " requests sent, showing " + showing + ")"
                    : "Completed: " + totalSent + " requests sent, showing " + showing);

                if (!sessionController.isRunning()) {
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    setAttackControlsEnabled(true);
                }

            } catch (Exception e) {
                api.logging().logToError("Error in addResult: " + e.getMessage());
            }
        });
    }

    private void handleSessionStateChange(SessionState state) {
        SwingUtilities.invokeLater(() -> {
            if (state == SessionState.RUNNING) {
                statusLabel.setText("Fuzzing in progress...");
                startButton.setEnabled(false);
                stopButton.setEnabled(true);
                setAttackControlsEnabled(false);
                return;
            }

            if (shuttingDown && state != SessionState.DISPOSED) {
                return;
            }

            int totalSent = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();

            switch (state) {
                case STOPPED -> updateIdleUi("Stopped: " + totalSent + " requests sent, showing " + showing);
                case COMPLETED -> updateIdleUi("Completed: " + totalSent + " requests sent, showing " + showing);
                case DISPOSED -> {
                    startButton.setEnabled(false);
                    stopButton.setEnabled(false);
                }
                default -> {
                }
            }
        });
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        setAttackControlsEnabled(true);
    }

    private void setAttackControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        attackSelectionPanel.setControlsEnabled(enabled);
        runOptionsPanel.setControlsEnabled(enabled, isCollaboratorAvailable());
    }

    private boolean isCollaboratorAvailable() {
        return !shuttingDown && CollaboratorSupport.isAvailable(api);
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value == null ? "" : value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }
}
