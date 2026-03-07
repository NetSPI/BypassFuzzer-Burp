package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;
import com.bypassfuzzer.burp.http.RequestPathUtils;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.session.SessionPreflightAnalyzer;
import com.bypassfuzzer.burp.session.SessionRunOptions;
import com.bypassfuzzer.burp.session.SessionState;
import com.bypassfuzzer.burp.ui.session.AttackSelectionPanel;
import com.bypassfuzzer.burp.ui.session.FilterPanel;
import com.bypassfuzzer.burp.ui.session.RunOptionsPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsPanel;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
    private final ResultFilterController filterController = new ResultFilterController();

    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private AttackSelectionPanel attackSelectionPanel;
    private RunOptionsPanel runOptionsPanel;
    private FilterPanel filterPanel;
    private SessionResultsPanel resultsPanel;

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
    }

    private void initializeUi() {
        setLayout(new BorderLayout());
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);

        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(new JLabel(String.format("Target: %s %s", request.method(), request.url())));
        add(infoPanel, BorderLayout.SOUTH);
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
        filterPanel = new FilterPanel(filterController.filterConfig(), message -> api.logging().logToError(message));
        filterPanel.setFilterChangeListener(this::applyFilters);

        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        filterScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        filterScrollPane.setMinimumSize(new Dimension(250, 100));

        resultsPanel = new SessionResultsPanel(api, filterController.highlighter(), this::applyFilters);

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filterScrollPane, resultsPanel);
        horizontalSplit.setDividerSize(6);
        horizontalSplit.setResizeWeight(0.0);
        SwingUtilities.invokeLater(() -> horizontalSplit.setDividerLocation(500));
        return horizontalSplit;
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
        int requestsPerSecond;
        try {
            requestsPerSecond = Math.max(0, Integer.parseInt(runOptionsPanel.requestsPerSecondText().trim()));
        } catch (NumberFormatException e) {
            requestsPerSecond = 0;
        }

        return new SessionRunOptions(
            attackSelectionPanel.isHeaderAttackEnabled(),
            attackSelectionPanel.isPathAttackEnabled(),
            attackSelectionPanel.isVerbAttackEnabled(),
            attackSelectionPanel.isParamAttackEnabled(),
            attackSelectionPanel.isTrailingDotAttackEnabled(),
            attackSelectionPanel.isTrailingSlashAttackEnabled(),
            attackSelectionPanel.isExtensionAttackEnabled(),
            attackSelectionPanel.isContentTypeAttackEnabled(),
            attackSelectionPanel.isEncodingAttackEnabled(),
            attackSelectionPanel.isProtocolAttackEnabled(),
            attackSelectionPanel.isCaseAttackEnabled(),
            runOptionsPanel.isCollaboratorEnabled(),
            attackSelectionPanel.isCookieParamAttackEnabled(),
            runOptionsPanel.isFuzzExistingCookiesEnabled(),
            requestsPerSecond,
            parseStatusCodes(runOptionsPanel.throttleStatusCodesText())
        );
    }

    private void clearResults() {
        resultsPanel.clear();
        filterController.reset();
        statusLabel.setText("Results cleared");
        updateFilterStatus();
    }

    private void applyFilters() {
        filterController.setHighlightColorFilter(filterPanel.selectedHighlightColor());
        resultsPanel.applyFilter(filterController::shouldShow);
        updateFilterStatus();
        api.logging().logToOutput(
            "Filters applied: showing " + resultsPanel.shownResultsCount() + " of " + resultsPanel.allResultsCount() + " results"
        );
    }

    private void addResult(AttackResult result) {
        SwingUtilities.invokeLater(() -> {
            try {
                filterController.track(result);
                resultsPanel.addResult(result, filterController.shouldShow(result));

                int totalSent = resultsPanel.allResultsCount();
                int showing = resultsPanel.shownResultsCount();
                statusLabel.setText(sessionController.isRunning()
                    ? "Fuzzing... (" + totalSent + " requests sent, showing " + showing + ")"
                    : "Completed: " + totalSent + " requests sent, showing " + showing);

                if (!sessionController.isRunning()) {
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    setAttackControlsEnabled(true);
                }

                updateFilterStatus();
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

            int totalSent = resultsPanel.allResultsCount();
            int showing = resultsPanel.shownResultsCount();

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

    private void updateFilterStatus() {
        filterPanel.setFilterStatus(
            filterController.statusText(resultsPanel.shownResultsCount(), resultsPanel.allResultsCount())
        );
    }

    private void setAttackControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        attackSelectionPanel.setControlsEnabled(enabled);
        runOptionsPanel.setControlsEnabled(enabled, isCollaboratorAvailable());
    }

    private boolean isCollaboratorAvailable() {
        if (shuttingDown) {
            return false;
        }
        try {
            return api.collaborator() != null && api.collaborator().defaultPayloadGenerator() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value == null ? "" : value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }

    private Set<Integer> parseStatusCodes(String input) {
        if (input == null || input.trim().isEmpty()) {
            return Set.of();
        }

        return java.util.Arrays.stream(input.split(","))
            .map(String::trim)
            .filter(token -> !token.isEmpty())
            .map(token -> {
                try {
                    int code = Integer.parseInt(token);
                    return code >= 100 && code < 600 ? code : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            })
            .filter(java.util.Objects::nonNull)
            .collect(Collectors.toSet());
    }
}
