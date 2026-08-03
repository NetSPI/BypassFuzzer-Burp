package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepCandidate;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepAuthSelection;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepClassifier;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepEngine;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepMode;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbe;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPreview;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

public class CoverageSweepPanel extends JPanel {

    private final MontoyaApi api;
    private final CoverageSweepEngine engine;
    private final CandidateTableModel candidateTableModel = new CandidateTableModel();

    private JButton loadButton;
    private JButton importButton;
    private JButton startButton;
    private JButton stopButton;
    private JButton clearButton;
    private JButton previewProbesButton;
    private JButton viewCandidateButton;
    private JButton exportButton;
    private JButton authIdentifiersButton;
    private JComboBox<String> modeComboBox;
    private JCheckBox includeUnsafeMethodsCheckBox;
    private JCheckBox excludeStaticAssetsCheckBox;
    private JCheckBox verifyUnauthenticatedAccessCheckBox;
    private JCheckBox likelyPublicOnlyCheckBox;
    private JCheckBox status401CheckBox;
    private JCheckBox status403CheckBox;
    private JCheckBox status3xxCheckBox;
    private JCheckBox status4xxCheckBox;
    private JTextField concurrencyField;
    private JTextField throttleStatusCodesField;
    private JTextField requestDelayField;
    private JLabel statusLabel;
    private JLabel estimateLabel;
    private JLabel pullResponsesLabel;
    private JTable candidateTable;
    private SessionResultsWorkspace resultsWorkspace;
    private volatile boolean stopRequested = false;
    private List<CoverageSweepCandidate> cachedHistoryCandidates = List.of();
    private Set<String> discoveredAuthHeaders = Set.of();
    private Set<String> discoveredCookieNames = Set.of();
    private Set<String> selectedAuthHeaders = new LinkedHashSet<>(Set.of("Authorization"));
    private Set<String> selectedCookieNames = new LinkedHashSet<>();
    private final Map<HttpRequest, HttpResponse> importedControlResponses = new IdentityHashMap<>();
    private volatile SwingWorker<CoverageSweepPreview, Void> candidateLoadWorker;
    private boolean authDefaultsInitialized;

    public CoverageSweepPanel(MontoyaApi api) {
        this(api, new CoverageSweepEngine(api));
    }

    CoverageSweepPanel(MontoyaApi api, CoverageSweepEngine engine) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        initializeUi();
    }

    public void cleanup() {
        SwingWorker<CoverageSweepPreview, Void> worker = candidateLoadWorker;
        candidateLoadWorker = null;
        if (worker != null) {
            worker.cancel(true);
        }
        engine.cleanup();
    }

    private void initializeUi() {
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel executionRow = new JPanel(new FlowLayout(FlowLayout.LEFT));

        modeComboBox = new JComboBox<>(new String[]{
            "Blocked responses",
            "Authenticated traffic",
            "Import targets"
        });
        modeComboBox.addActionListener(e -> handleModeChange());

        status401CheckBox = new JCheckBox("401", true);
        status403CheckBox = new JCheckBox("403", true);
        status3xxCheckBox = new JCheckBox("3xx", false);
        status4xxCheckBox = new JCheckBox("4xx", false);
        status401CheckBox.addActionListener(e -> updateEstimate());
        status403CheckBox.addActionListener(e -> updateEstimate());
        status3xxCheckBox.addActionListener(e -> updateEstimate());
        status4xxCheckBox.addActionListener(e -> updateEstimate());

        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        concurrencyField = new JTextField(String.valueOf(defaults.concurrency()), 4);
        throttleStatusCodesField = new JTextField(formatStatusCodes(defaults.throttleStatusCodes()), 8);
        requestDelayField = new JTextField(String.valueOf(defaults.requestDelayMs()), 5);

        statusRow.add(new JLabel("Mode:"));
        statusRow.add(modeComboBox);
        pullResponsesLabel = new JLabel("Pull responses:");
        statusRow.add(pullResponsesLabel);
        statusRow.add(status401CheckBox);
        statusRow.add(status403CheckBox);
        statusRow.add(status3xxCheckBox);
        statusRow.add(status4xxCheckBox);

        includeUnsafeMethodsCheckBox = new JCheckBox("Include state-changing methods", false);
        includeUnsafeMethodsCheckBox.addActionListener(e -> refilterAuthenticatedCandidates());
        excludeStaticAssetsCheckBox = new JCheckBox("Exclude static assets", true);
        excludeStaticAssetsCheckBox.setToolTipText(
            "Skip image, JavaScript, CSS, and WOFF responses when loading authenticated Proxy history.");
        verifyUnauthenticatedAccessCheckBox = new JCheckBox("Verify unauthenticated access", true);
        verifyUnauthenticatedAccessCheckBox.setToolTipText(
            "Replay each authenticated candidate without credentials and mark successful 2xx responses as LIKELY PUBLIC.");
        authIdentifiersButton = new JButton("Auth Identifiers...");
        authIdentifiersButton.addActionListener(e -> openAuthIdentifiersDialog());

        executionRow.add(new JLabel("Concurrency:"));
        executionRow.add(concurrencyField);
        executionRow.add(new JLabel("Delay (ms):"));
        executionRow.add(requestDelayField);
        executionRow.add(new JLabel("Throttle codes:"));
        executionRow.add(throttleStatusCodesField);
        executionRow.add(includeUnsafeMethodsCheckBox);
        executionRow.add(excludeStaticAssetsCheckBox);
        executionRow.add(verifyUnauthenticatedAccessCheckBox);
        executionRow.add(authIdentifiersButton);

        loadButton = new JButton("Load from Proxy History");
        loadButton.addActionListener(e -> loadCandidates());
        importButton = new JButton("Import Targets");
        importButton.addActionListener(e -> importTargetsWithChooser());
        startButton = new JButton("Start Sweep");
        startButton.setEnabled(false);
        startButton.addActionListener(e -> startSweep());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopSweep());
        previewProbesButton = new JButton("Preview Probes");
        previewProbesButton.setEnabled(false);
        previewProbesButton.addActionListener(e -> openProbePreview());
        viewCandidateButton = new JButton("View");
        viewCandidateButton.setEnabled(false);
        viewCandidateButton.addActionListener(e -> openCandidateView());
        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        exportButton = new JButton("Export TSV");
        exportButton.setEnabled(false);
        exportButton.addActionListener(e -> exportResultsWithChooser());
        likelyPublicOnlyCheckBox = new JCheckBox("Likely Public only", false);
        likelyPublicOnlyCheckBox.setToolTipText("Show only direct unauthenticated-access candidates; all results remain retained.");
        likelyPublicOnlyCheckBox.addActionListener(e -> updateLikelyPublicFilter());

        statusRow.add(loadButton);
        statusRow.add(importButton);
        statusRow.add(viewCandidateButton);
        statusRow.add(previewProbesButton);
        statusRow.add(startButton);
        statusRow.add(stopButton);
        statusRow.add(clearButton);
        statusRow.add(exportButton);
        statusRow.add(likelyPublicOnlyCheckBox);

        controls.add(statusRow);
        controls.add(executionRow);

        statusLabel = new JLabel("Load in-scope Proxy history responses to preview sweep candidates.");
        estimateLabel = new JLabel("No candidates loaded.");

        JPanel labels = new JPanel(new FlowLayout(FlowLayout.LEFT));
        labels.add(statusLabel);
        labels.add(estimateLabel);

        panel.add(controls, BorderLayout.NORTH);
        panel.add(labels, BorderLayout.CENTER);
        updateModeControls();
        return panel;
    }

    private JSplitPane buildCenterPanel() {
        candidateTable = new JTable(candidateTableModel);
        candidateTableModel.addTableModelListener(e -> {
            updateEstimate();
            updatePreviewButton();
            if (!engine.isRunning() && startButton != null) {
                startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
            }
        });
        candidateTable.getColumnModel().getColumn(0).setMaxWidth(55);
        candidateTable.getColumnModel().getColumn(1).setMaxWidth(72);
        candidateTable.getColumnModel().getColumn(4).setMaxWidth(70);
        candidateTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updatePreviewButton();
            }
        });
        JScrollPane previewScrollPane = new JScrollPane(candidateTable);
        previewScrollPane.setBorder(BorderFactory.createTitledBorder("Candidates"));

        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> {
                updateExportButton();
                api.logging().logToOutput(
                    "Coverage sweep filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
                );
            },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.COVERAGE_SWEEP,
            false
        );

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, previewScrollPane, resultsWorkspace.component());
        splitPane.setResizeWeight(0.25);
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(220));
        return splitPane;
    }

    private void loadCandidates() {
        CoverageSweepOptions currentOptions = currentOptions();
        if (currentOptions.mode() == CoverageSweepMode.BLOCKED_RESPONSES && currentOptions.statuses().isEmpty()) {
            statusLabel.setText("Select at least one response status group before loading Proxy history.");
            startButton.setEnabled(false);
            return;
        }

        setControlsForLoading();
        if (!SwingUtilities.isEventDispatchThread()) {
            loadCandidatesSynchronously(currentOptions);
            return;
        }

        candidateLoadWorker = new SwingWorker<>() {
            @Override
            protected CoverageSweepPreview doInBackground() {
                return engine.collectPreview(currentOptions);
            }

            @Override
            protected void done() {
                if (candidateLoadWorker != this) {
                    return;
                }
                try {
                    applyLoadedCandidates(get(), currentOptions);
                } catch (CancellationException e) {
                    statusLabel.setText("Proxy history loading cancelled.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    handleCandidateLoadFailure(e);
                } catch (ExecutionException e) {
                    handleCandidateLoadFailure(e.getCause() == null ? e : e.getCause());
                } finally {
                    candidateLoadWorker = null;
                    finishCandidateLoading();
                }
            }
        };
        candidateLoadWorker.execute();
    }

    private void loadCandidatesSynchronously(CoverageSweepOptions options) {
        try {
            applyLoadedCandidates(engine.collectPreview(options), options);
        } catch (Exception e) {
            handleCandidateLoadFailure(e);
        } finally {
            finishCandidateLoading();
        }
    }

    private void applyLoadedCandidates(CoverageSweepPreview preview, CoverageSweepOptions options) {
        cachedHistoryCandidates = preview.candidates();
        discoveredAuthHeaders = preview.discoveredHeaderNames();
        discoveredCookieNames = preview.discoveredCookieNames();
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            if (!authDefaultsInitialized) {
                selectObviousIdentifiers();
                authDefaultsInitialized = true;
            }
            refilterAuthenticatedCandidates();
        } else {
            setCandidateRows(preview.candidates());
        }
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        updatePreviewButton();
        statusLabel.setText("Found " + preview.blockedHistoryCount()
            + " matching history items; " + preview.dedupedEndpointCount()
            + " deduped endpoints; showing " + preview.candidates().size() + ".");
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            updateAuthenticatedStatus(preview.blockedHistoryCount(), preview.dedupedEndpointCount());
        }
        updateEstimate();
    }

    private void handleCandidateLoadFailure(Throwable error) {
        String message = error == null || error.getMessage() == null
            ? "unknown error" : error.getMessage();
        statusLabel.setText("Unable to load Proxy history: " + message);
        startButton.setEnabled(false);
        setCandidateActionButtonsEnabled(false);
    }

    private void finishCandidateLoading() {
        loadButton.setEnabled(true);
        importButton.setEnabled(true);
        setStatusControlsEnabled(true);
        candidateTableModel.setSelectionEditingEnabled(true);
        updatePreviewButton();
    }

    private void importTargetsWithChooser() {
        if (currentMode() != CoverageSweepMode.IMPORTED_TARGETS) {
            statusLabel.setText("Select Import targets mode to load a URL list.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Sweep Targets");
        int result = chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        importTargetsFromFile(chooser.getSelectedFile().toPath());
    }

    boolean importTargetsFromFile(Path path) {
        setControlsForLoading();
        try {
            List<String> urls = Files.readAllLines(path);
            CoverageSweepPreview preview = engine.collectPreviewFromUrls(urls, currentOptions());
            setCandidateRows(preview.candidates());
            startButton.setEnabled(!preview.candidates().isEmpty());
            updatePreviewButton();
            statusLabel.setText("Imported " + preview.blockedHistoryCount()
                + " valid target URL(s); " + preview.dedupedEndpointCount()
                + " deduped endpoints; showing " + preview.candidates().size() + ".");
            updateEstimate();
            return true;
        } catch (Exception e) {
            setCandidateRows(List.of());
            statusLabel.setText("Unable to import targets: " + e.getMessage());
            startButton.setEnabled(false);
            setCandidateActionButtonsEnabled(false);
            return false;
        } finally {
            finishCandidateLoading();
        }
    }

    private void startSweep() {
        List<CoverageSweepCandidate> selected = candidateTableModel.selectedCandidates();
        if (selected.isEmpty()) {
            statusLabel.setText("Select at least one candidate before starting.");
            return;
        }

        stopRequested = false;
        loadButton.setEnabled(false);
        importButton.setEnabled(false);
        setStatusControlsEnabled(false);
        candidateTableModel.setSelectionEditingEnabled(false);
        previewProbesButton.setEnabled(false);
        viewCandidateButton.setEnabled(previewCandidate() != null);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        candidateTable.setEnabled(true);
        statusLabel.setText("Coverage sweep in progress...");

        if (!engine.start(selected, currentOptions(), this::addResult, this::handleCompletion)) {
            updateIdleUi("Unable to start coverage sweep.");
        }
    }

    private void stopSweep() {
        stopRequested = true;
        stopButton.setEnabled(false);
        statusLabel.setText("Stopping coverage sweep...");
        engine.stop();
    }

    private void clearResults() {
        resultsWorkspace.clear();
        updateExportButton();
        statusLabel.setText("Coverage sweep results cleared.");
    }

    private void addResult(AttackResult result) {
        SwingUtilities.invokeLater(() -> {
            if (result.getOriginalRequest() != null && result.getOriginalResponse() != null) {
                importedControlResponses.put(result.getOriginalRequest(), result.getOriginalResponse());
            }
            resultsWorkspace.addResult(result);
            updateExportButton();
            statusLabel.setText("Coverage sweep running: " + resultsWorkspace.allResultsCount() + " requests sent.");
        });
    }

    private void handleCompletion() {
        SwingUtilities.invokeLater(() -> updateIdleUi(
            (stopRequested ? "Stopped" : "Completed")
                + ": " + resultsWorkspace.allResultsCount() + " requests sent."
        ));
    }

    private void setControlsForLoading() {
        loadButton.setEnabled(false);
        importButton.setEnabled(false);
        setStatusControlsEnabled(false);
        setCandidateActionButtonsEnabled(false);
        candidateTableModel.setSelectionEditingEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        statusLabel.setText("Loading Proxy history...");
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        loadButton.setEnabled(true);
        importButton.setEnabled(true);
        setStatusControlsEnabled(true);
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        stopButton.setEnabled(false);
        candidateTable.setEnabled(true);
        candidateTableModel.setSelectionEditingEnabled(true);
        updateEstimate();
        updatePreviewButton();
    }

    private void updateEstimate() {
        int selected = candidateTableModel.selectedCandidates().size();
        int estimate = selected * currentOptions().maxProbesPerCandidate();
        estimateLabel.setText("Selected " + selected + " endpoint(s); estimated max " + estimate + " request(s).");
    }

    private CoverageSweepOptions currentOptions() {
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        return new CoverageSweepOptions(
            selectedStatuses(),
            defaults.inScopeOnly(),
            defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(),
            parsePositiveInt(concurrencyField, defaults.concurrency()),
            defaults.requestsPerSecond(),
            parseNonNegativeInt(requestDelayField, defaults.requestDelayMs()),
            SessionInputParsers.parseStatusCodes(throttleStatusCodesField.getText()),
            currentMode(),
            currentAuthSelection(),
            excludeStaticAssetsCheckBox == null || excludeStaticAssetsCheckBox.isSelected(),
            verifyUnauthenticatedAccessCheckBox != null && verifyUnauthenticatedAccessCheckBox.isSelected()
        );
    }

    private Set<Integer> selectedStatuses() {
        Set<Integer> statuses = new LinkedHashSet<>();
        if (status401CheckBox != null && status401CheckBox.isSelected()) {
            statuses.add(401);
        }
        if (status403CheckBox != null && status403CheckBox.isSelected()) {
            statuses.add(403);
        }
        if (status3xxCheckBox != null && status3xxCheckBox.isSelected()) {
            addRange(statuses, 300, 399);
        }
        if (status4xxCheckBox != null && status4xxCheckBox.isSelected()) {
            addRange(statuses, 400, 499);
        }
        return Set.copyOf(statuses);
    }

    private void addRange(Set<Integer> statuses, int start, int end) {
        for (int status = start; status <= end; status++) {
            statuses.add(status);
        }
    }

    private void setStatusControlsEnabled(boolean enabled) {
        status401CheckBox.setEnabled(enabled);
        status403CheckBox.setEnabled(enabled);
        status3xxCheckBox.setEnabled(enabled);
        status4xxCheckBox.setEnabled(enabled);
        concurrencyField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);
        requestDelayField.setEnabled(enabled);
        modeComboBox.setEnabled(enabled);
        updateModeControls();
    }

    private CoverageSweepMode currentMode() {
        if (modeComboBox == null) {
            return CoverageSweepMode.BLOCKED_RESPONSES;
        }
        return switch (modeComboBox.getSelectedIndex()) {
            case 1 -> CoverageSweepMode.AUTHENTICATED_TRAFFIC;
            case 2 -> CoverageSweepMode.IMPORTED_TARGETS;
            default -> CoverageSweepMode.BLOCKED_RESPONSES;
        };
    }

    private CoverageSweepAuthSelection currentAuthSelection() {
        return new CoverageSweepAuthSelection(selectedAuthHeaders, selectedCookieNames,
            includeUnsafeMethodsCheckBox != null && includeUnsafeMethodsCheckBox.isSelected());
    }

    private void handleModeChange() {
        cachedHistoryCandidates = List.of();
        setCandidateRows(List.of());
        if (likelyPublicOnlyCheckBox != null) {
            likelyPublicOnlyCheckBox.setSelected(false);
        }
        updateLikelyPublicFilter();
        startButton.setEnabled(false);
        updateModeControls();
        statusLabel.setText(switch (currentMode()) {
            case AUTHENTICATED_TRAFFIC ->
                "Load in-scope 2xx Proxy history and choose identifiers used to recognize authenticated requests.";
            case IMPORTED_TARGETS ->
                "Import a text file containing one absolute HTTP or HTTPS URL per line.";
            case BLOCKED_RESPONSES ->
                "Load in-scope Proxy history responses to preview sweep candidates.";
        });
        updateEstimate();
    }

    private void updateModeControls() {
        if (modeComboBox == null) return;
        boolean idle = !engine.isRunning() && modeComboBox.isEnabled();
        boolean authenticated = currentMode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC;
        boolean imported = currentMode() == CoverageSweepMode.IMPORTED_TARGETS;
        boolean blocked = currentMode() == CoverageSweepMode.BLOCKED_RESPONSES;
        pullResponsesLabel.setVisible(blocked);
        status401CheckBox.setVisible(blocked);
        status403CheckBox.setVisible(blocked);
        status3xxCheckBox.setVisible(blocked);
        status4xxCheckBox.setVisible(blocked);
        status401CheckBox.setEnabled(idle && blocked);
        status403CheckBox.setEnabled(idle && blocked);
        status3xxCheckBox.setEnabled(idle && blocked);
        status4xxCheckBox.setEnabled(idle && blocked);
        loadButton.setVisible(!imported);
        loadButton.setEnabled(idle && !imported);
        importButton.setVisible(imported);
        importButton.setEnabled(idle && imported);
        includeUnsafeMethodsCheckBox.setEnabled(idle && authenticated);
        excludeStaticAssetsCheckBox.setEnabled(idle && authenticated);
        verifyUnauthenticatedAccessCheckBox.setVisible(authenticated);
        verifyUnauthenticatedAccessCheckBox.setEnabled(idle && authenticated);
        authIdentifiersButton.setEnabled(idle && authenticated);
        likelyPublicOnlyCheckBox.setVisible(authenticated);
        likelyPublicOnlyCheckBox.setEnabled(authenticated);
        loadButton.setText(authenticated ? "Load Authenticated History" : "Load from Proxy History");
        revalidate();
        repaint();
    }

    private void selectObviousIdentifiers() {
        selectedAuthHeaders.add("Authorization");
        for (String header : discoveredAuthHeaders) {
            if (looksLikeAuthIdentifier(header)) selectedAuthHeaders.add(header);
        }
        for (String cookie : discoveredCookieNames) {
            if (looksLikeAuthIdentifier(cookie)) selectedCookieNames.add(cookie);
        }
    }

    private boolean looksLikeAuthIdentifier(String name) {
        String lower = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("auth") || lower.contains("session") || lower.contains("token")
            || lower.contains("jwt") || lower.equals("sid") || lower.endsWith("sid")
            || lower.contains("api-key") || lower.contains("apikey");
    }

    private void refilterAuthenticatedCandidates() {
        if (currentMode() != CoverageSweepMode.AUTHENTICATED_TRAFFIC) return;
        CoverageSweepAuthSelection selection = currentAuthSelection();
        List<CoverageSweepCandidate> filtered = cachedHistoryCandidates.stream()
            .filter(candidate -> selection.includeUnsafeMethods()
                || "GET".equalsIgnoreCase(candidate.method()) || "HEAD".equalsIgnoreCase(candidate.method()))
            .filter(candidate -> engine.matchesAuthSelection(candidate, selection))
            .limit(Math.max(1, CoverageSweepOptions.defaults().maxCandidates()))
            .toList();
        setCandidateRows(filtered);
        startButton.setEnabled(!filtered.isEmpty() && !engine.isRunning());
        updateAuthenticatedStatus(cachedHistoryCandidates.size(), cachedHistoryCandidates.size());
        updateEstimate();
        updatePreviewButton();
    }

    private void setCandidateRows(List<CoverageSweepCandidate> candidates) {
        importedControlResponses.clear();
        candidateTableModel.setCandidates(candidates);
        if (candidates == null || candidates.isEmpty()) {
            candidateTable.clearSelection();
            return;
        }
        candidateTable.setRowSelectionInterval(0, 0);
    }

    private void updateAuthenticatedStatus(int historyCount, int dedupedCount) {
        statusLabel.setText("Inspected " + historyCount + " in-scope 2xx history item(s); "
            + dedupedCount + " deduped; " + candidateTableModel.getRowCount()
            + " match the selected auth identifiers.");
    }

    private void updateLikelyPublicFilter() {
        if (resultsWorkspace == null) {
            return;
        }
        boolean enabled = likelyPublicOnlyCheckBox != null && likelyPublicOnlyCheckBox.isSelected();
        resultsWorkspace.setExternalFilter(enabled
            ? result -> result.getPayloadEncoding() != null
                && result.getPayloadEncoding().startsWith(CoverageSweepClassifier.LIKELY_PUBLIC_PREFIX)
            : result -> true);
    }

    private void openAuthIdentifiersDialog() {
        JPanel choices = new JPanel();
        choices.setLayout(new BoxLayout(choices, BoxLayout.Y_AXIS));
        choices.add(new JLabel("Headers used to identify authenticated requests:"));
        List<JCheckBox> headerBoxes = new ArrayList<>();
        Set<String> headers = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        headers.add("Authorization");
        headers.addAll(discoveredAuthHeaders);
        headers.addAll(selectedAuthHeaders);
        for (String name : headers) {
            JCheckBox box = new JCheckBox(name, selectedAuthHeaders.stream().anyMatch(name::equalsIgnoreCase));
            box.putClientProperty("identifier", name);
            headerBoxes.add(box);
            choices.add(box);
        }
        choices.add(new JLabel("Additional auth header names (comma-separated):"));
        JTextField customHeaders = new JTextField(30);
        choices.add(customHeaders);
        choices.add(new JLabel("Cookie names used only to identify authenticated requests:"));
        List<JCheckBox> cookieBoxes = new ArrayList<>();
        for (String name : new java.util.TreeSet<>(discoveredCookieNames)) {
            JCheckBox box = new JCheckBox(name, selectedCookieNames.contains(name));
            box.putClientProperty("identifier", name);
            cookieBoxes.add(box);
            choices.add(box);
        }
        choices.add(new JLabel("The entire Cookie header is removed from every attack request."));
        JScrollPane scroll = new JScrollPane(choices);
        scroll.setPreferredSize(new Dimension(520, 420));
        int result = JOptionPane.showConfirmDialog(this, scroll, "Authenticated Traffic Identifiers",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;
        selectedAuthHeaders = selectedIdentifiers(headerBoxes);
        for (String value : customHeaders.getText().split(",")) {
            if (!value.isBlank()) selectedAuthHeaders.add(value.trim());
        }
        selectedCookieNames = selectedIdentifiers(cookieBoxes);
        refilterAuthenticatedCandidates();
    }

    private Set<String> selectedIdentifiers(List<JCheckBox> boxes) {
        Set<String> selected = new LinkedHashSet<>();
        for (JCheckBox box : boxes) {
            if (box.isSelected()) selected.add(String.valueOf(box.getClientProperty("identifier")));
        }
        return selected;
    }

    private int parsePositiveInt(JTextField field, int fallback) {
        try {
            return Math.max(1, Integer.parseInt(field.getText().trim()));
        } catch (Exception e) {
            return fallback;
        }
    }

    private int parseNonNegativeInt(JTextField field, int fallback) {
        try {
            return Math.max(0, Integer.parseInt(field.getText().trim()));
        } catch (Exception e) {
            return fallback;
        }
    }

    private String formatStatusCodes(Set<Integer> codes) {
        if (codes == null || codes.isEmpty()) {
            return "";
        }
        return codes.stream()
            .sorted()
            .map(String::valueOf)
            .collect(java.util.stream.Collectors.joining(","));
    }

    private void updatePreviewButton() {
        boolean candidateAvailable = previewCandidate() != null;
        previewProbesButton.setEnabled(candidateAvailable && !engine.isRunning());
        viewCandidateButton.setEnabled(candidateAvailable && candidateLoadWorker == null);
    }

    private void setCandidateActionButtonsEnabled(boolean enabled) {
        if (previewProbesButton != null) previewProbesButton.setEnabled(enabled);
        if (viewCandidateButton != null) viewCandidateButton.setEnabled(enabled);
    }

    private void updateExportButton() {
        if (exportButton != null) {
            exportButton.setEnabled(resultsWorkspace != null && resultsWorkspace.shownResultsCount() > 0);
        }
    }

    private void exportResultsWithChooser() {
        if (resultsWorkspace.shownResultsCount() == 0) {
            statusLabel.setText("No visible sweep results to export.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Sweep Results TSV");
        chooser.setSelectedFile(new java.io.File("bypassfuzzer-sweep-results.tsv"));
        int result = chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        exportResultsToTsv(chooser.getSelectedFile().toPath());
    }

    boolean exportResultsToTsv(Path path) {
        if (resultsWorkspace.shownResultsCount() == 0) {
            statusLabel.setText("No visible sweep results to export.");
            return false;
        }

        try {
            resultsWorkspace.writeVisibleResultsTsv(path);
            statusLabel.setText("Exported " + resultsWorkspace.shownResultsCount()
                + " visible sweep result(s) to " + path + ".");
            return true;
        } catch (Exception e) {
            statusLabel.setText("Unable to export sweep results: " + e.getMessage());
            try {
                JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Unable to export sweep results:\n" + e.getMessage(),
                    "Export Failed",
                    JOptionPane.ERROR_MESSAGE
                );
            } catch (Exception ignored) {
                // Headless tests or Burp shutdown can make dialogs unavailable.
            }
            return false;
        }
    }

    private CoverageSweepCandidate previewCandidate() {
        if (candidateTable == null || candidateTableModel.getRowCount() == 0) {
            return null;
        }
        int selectedViewRow = candidateTable.getSelectedRow();
        if (selectedViewRow >= 0) {
            return candidateTableModel.candidateAt(candidateTable.convertRowIndexToModel(selectedViewRow));
        }
        List<CoverageSweepCandidate> selectedCandidates = candidateTableModel.selectedCandidates();
        return selectedCandidates.isEmpty() ? null : selectedCandidates.get(0);
    }

    private void openCandidateView() {
        CoverageSweepCandidate candidate = previewCandidate();
        if (candidate == null) {
            statusLabel.setText("Select a candidate to view its original request and response.");
            return;
        }

        HttpRequestEditor requestViewer = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor responseViewer = api.userInterface().createHttpResponseEditor();
        requestViewer.setRequest(candidate.request());
        HttpResponse originalResponse = originalResponseFor(candidate);
        responseViewer.setResponse(originalResponse);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);

        JSplitPane exchangeSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        exchangeSplit.setResizeWeight(0.5);

        JDialog dialog = new JDialog(
            api.userInterface().swingUtils().suiteFrame(),
            "Sweep Target - " + candidate.method() + " " + candidate.displayUrl(),
            false
        );
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(0, 8));
        dialog.add(exchangeSplit, BorderLayout.CENTER);
        if (originalResponse == null) {
            JLabel note = new JLabel("No response is available until the imported target's Control request runs.");
            note.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
            dialog.add(note, BorderLayout.SOUTH);
        }
        dialog.setSize(1200, 720);
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        SwingUtilities.invokeLater(() -> exchangeSplit.setDividerLocation(0.5));
        dialog.setVisible(true);
    }

    private HttpResponse originalResponseFor(CoverageSweepCandidate candidate) {
        if (candidate == null) {
            return null;
        }
        return candidate.originalResponse() != null
            ? candidate.originalResponse()
            : importedControlResponses.get(candidate.request());
    }

    private void openProbePreview() {
        CoverageSweepCandidate candidate = previewCandidate();
        if (candidate == null) {
            statusLabel.setText("Select or check a candidate before previewing probes.");
            return;
        }

        List<CoverageSweepProbe> probes = engine.buildProbes(candidate, currentOptions());
        JTextArea previewText = new JTextArea(renderProbePreview(candidate, probes));
        previewText.setEditable(false);
        previewText.setLineWrap(false);
        previewText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewText.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(previewText);
        scrollPane.setPreferredSize(new Dimension(920, 620));

        JDialog dialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Sweep Probe Preview", false);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(0, 8));

        JLabel header = new JLabel(candidate.method() + " " + candidate.displayUrl() + " - " + probes.size() + " probe(s)");
        header.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
        dialog.add(header, BorderLayout.NORTH);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.pack();
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        dialog.setVisible(true);
    }

    String renderProbePreview(CoverageSweepCandidate candidate, List<CoverageSweepProbe> probes) {
        StringBuilder builder = new StringBuilder();
        builder.append("Candidate: ")
            .append(candidate.method())
            .append(" ")
            .append(candidate.displayUrl())
            .append(System.lineSeparator())
            .append("Status: ")
            .append(candidate.statusCode())
            .append(System.lineSeparator())
            .append("Probe count: ")
            .append(probes.size())
            .append(System.lineSeparator())
            .append(System.lineSeparator());

        for (int index = 0; index < probes.size(); index++) {
            CoverageSweepProbe probe = probes.get(index);
            builder.append("===")
                .append(" ")
                .append(index + 1)
                .append(". ")
                .append(probe.family())
                .append(" - ")
                .append(probe.label())
                .append(" ")
                .append("===")
                .append(System.lineSeparator())
                .append(probe.request())
                .append(System.lineSeparator())
                .append(System.lineSeparator());
        }
        return builder.toString();
    }

    private static final class CandidateTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Run", "Method", "Host", "Path", "Status", "Content-Type"};
        private final List<Row> rows = new ArrayList<>();
        private boolean selectionEditingEnabled = true;

        void setSelectionEditingEnabled(boolean enabled) {
            selectionEditingEnabled = enabled;
            if (!rows.isEmpty()) {
                fireTableRowsUpdated(0, rows.size() - 1);
            }
        }

        void setCandidates(List<CoverageSweepCandidate> candidates) {
            rows.clear();
            for (CoverageSweepCandidate candidate : candidates) {
                rows.add(new Row(true, candidate));
            }
            fireTableDataChanged();
        }

        List<CoverageSweepCandidate> selectedCandidates() {
            return rows.stream()
                .filter(row -> row.selected)
                .map(row -> row.candidate)
                .toList();
        }

        CoverageSweepCandidate candidateAt(int rowIndex) {
            if (rowIndex < 0 || rowIndex >= rows.size()) {
                return null;
            }
            return rows.get(rowIndex).candidate;
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 0 ? Boolean.class : Object.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return selectionEditingEnabled && columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row row = rows.get(rowIndex);
            CoverageSweepCandidate candidate = row.candidate;
            return switch (columnIndex) {
                case 0 -> row.selected;
                case 1 -> candidate.method();
                case 2 -> candidate.host();
                case 3 -> candidate.path();
                case 4 -> candidate.originalResponse() == null ? "Imported" : candidate.statusCode();
                case 5 -> candidate.contentType();
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < rows.size()) {
                rows.get(rowIndex).selected = Boolean.TRUE.equals(value);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }

        private static final class Row {
            private boolean selected;
            private final CoverageSweepCandidate candidate;

            private Row(boolean selected, CoverageSweepCandidate candidate) {
                this.selected = selected;
                this.candidate = candidate;
            }
        }
    }
}
