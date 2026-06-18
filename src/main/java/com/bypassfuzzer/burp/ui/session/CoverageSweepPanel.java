package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepCandidate;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepEngine;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbe;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPreview;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.WindowConstants;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class CoverageSweepPanel extends JPanel {

    private final MontoyaApi api;
    private final CoverageSweepEngine engine;
    private final CandidateTableModel candidateTableModel = new CandidateTableModel();

    private JButton loadButton;
    private JButton startButton;
    private JButton stopButton;
    private JButton clearButton;
    private JButton previewProbesButton;
    private JCheckBox status401CheckBox;
    private JCheckBox status403CheckBox;
    private JCheckBox status3xxCheckBox;
    private JCheckBox status4xxCheckBox;
    private JLabel statusLabel;
    private JLabel estimateLabel;
    private JTable candidateTable;
    private SessionResultsWorkspace resultsWorkspace;
    private volatile boolean stopRequested = false;

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
        engine.cleanup();
    }

    private void initializeUi() {
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));

        status401CheckBox = new JCheckBox("401", true);
        status403CheckBox = new JCheckBox("403", true);
        status3xxCheckBox = new JCheckBox("3xx", false);
        status4xxCheckBox = new JCheckBox("4xx", false);
        status401CheckBox.addActionListener(e -> updateEstimate());
        status403CheckBox.addActionListener(e -> updateEstimate());
        status3xxCheckBox.addActionListener(e -> updateEstimate());
        status4xxCheckBox.addActionListener(e -> updateEstimate());

        controls.add(new JLabel("Pull responses:"));
        controls.add(status401CheckBox);
        controls.add(status403CheckBox);
        controls.add(status3xxCheckBox);
        controls.add(status4xxCheckBox);

        loadButton = new JButton("Load from Proxy History");
        loadButton.addActionListener(e -> loadCandidates());
        startButton = new JButton("Start Sweep");
        startButton.setEnabled(false);
        startButton.addActionListener(e -> startSweep());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopSweep());
        previewProbesButton = new JButton("Preview Probes");
        previewProbesButton.setEnabled(false);
        previewProbesButton.addActionListener(e -> openProbePreview());
        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());

        controls.add(loadButton);
        controls.add(previewProbesButton);
        controls.add(startButton);
        controls.add(stopButton);
        controls.add(clearButton);

        statusLabel = new JLabel("Load in-scope Proxy history responses to preview sweep candidates.");
        estimateLabel = new JLabel("No candidates loaded.");

        JPanel labels = new JPanel(new FlowLayout(FlowLayout.LEFT));
        labels.add(statusLabel);
        labels.add(estimateLabel);

        panel.add(controls, BorderLayout.NORTH);
        panel.add(labels, BorderLayout.CENTER);
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

        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> api.logging().logToOutput(
                "Coverage sweep filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
            ),
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
        if (currentOptions.statuses().isEmpty()) {
            statusLabel.setText("Select at least one response status group before loading Proxy history.");
            startButton.setEnabled(false);
            return;
        }

        setControlsForLoading();
        try {
            CoverageSweepPreview preview = engine.collectPreview(currentOptions);
            candidateTableModel.setCandidates(preview.candidates());
            startButton.setEnabled(!preview.candidates().isEmpty());
            updatePreviewButton();
            statusLabel.setText("Found " + preview.blockedHistoryCount()
                + " matching history items; " + preview.dedupedEndpointCount()
                + " deduped endpoints; showing " + preview.candidates().size() + ".");
            updateEstimate();
        } catch (Exception e) {
            statusLabel.setText("Unable to load Proxy history: " + e.getMessage());
            startButton.setEnabled(false);
            previewProbesButton.setEnabled(false);
        } finally {
            loadButton.setEnabled(true);
            setStatusControlsEnabled(true);
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
        setStatusControlsEnabled(false);
        previewProbesButton.setEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        candidateTable.setEnabled(false);
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
        statusLabel.setText("Coverage sweep results cleared.");
    }

    private void addResult(AttackResult result) {
        SwingUtilities.invokeLater(() -> {
            resultsWorkspace.addResult(result);
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
        setStatusControlsEnabled(false);
        previewProbesButton.setEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        statusLabel.setText("Loading Proxy history...");
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        loadButton.setEnabled(true);
        setStatusControlsEnabled(true);
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        stopButton.setEnabled(false);
        candidateTable.setEnabled(true);
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
            defaults.requestsPerSecond(),
            defaults.throttleStatusCodes()
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
    }

    private void updatePreviewButton() {
        if (previewProbesButton != null) {
            previewProbesButton.setEnabled(!engine.isRunning() && previewCandidate() != null);
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
            return columnIndex == 0;
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
                case 4 -> candidate.statusCode();
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
