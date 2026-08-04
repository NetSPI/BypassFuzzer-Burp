package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * Shared filter/results workspace used by session tabs.
 */
public class SessionResultsWorkspace {

    private static final int SIDEBAR_WIDTH = 500;
    private static final int COLLAPSED_SIDEBAR_WIDTH = 58;

    private final ResultFilterController filterController = new ResultFilterController();
    private final FilterPanel filterPanel;
    private final SessionResultsPanel resultsPanel;
    private final JSplitPane splitPane;
    private final Consumer<SessionResultsWorkspace> filterAppliedListener;
    private boolean filtersCollapsed;

    public SessionResultsWorkspace(MontoyaApi api,
                                   Consumer<String> errorLogger,
                                   Consumer<SessionResultsWorkspace> filterAppliedListener,
                                   SessionResultsPanel.ViewerLayout viewerLayout,
                                   SessionResultsPanel.TableLayout tableLayout,
                                   boolean borderlessSidebar) {
        this.filterAppliedListener = filterAppliedListener == null ? workspace -> { } : filterAppliedListener;
        this.filterPanel = new FilterPanel(filterController.filterConfig(), errorLogger);
        this.filterPanel.setFilterChangeListener(this::applyFilters);
        this.resultsPanel = new SessionResultsPanel(api, filterController.highlighter(), this::applyFilters, viewerLayout, tableLayout);
        this.splitPane = buildSplitPane(borderlessSidebar);
        updateFilterStatus();
    }

    public JSplitPane component() {
        return splitPane;
    }

    public void applyFilters() {
        filterController.setHighlightColorFilter(filterPanel.selectedHighlightColor());
        resultsPanel.applyFilter(filterController::shouldShow);
        updateFilterStatus();
        filterAppliedListener.accept(this);
    }

    public void addResult(AttackResult result) {
        filterController.track(result);
        resultsPanel.addResult(result, filterController.shouldShow(result));
        updateFilterStatus();
    }

    public void clear() {
        resultsPanel.clear();
        filterController.reset();
        updateFilterStatus();
    }

    public int shownResultsCount() {
        return resultsPanel.shownResultsCount();
    }

    public int allResultsCount() {
        return resultsPanel.allResultsCount();
    }

    public String visibleResultsAsTsv() {
        return resultsPanel.visibleRowsAsTsv();
    }

    public void writeVisibleResultsTsv(Path path) throws IOException {
        Files.writeString(path, visibleResultsAsTsv(), StandardCharsets.UTF_8);
    }

    private JSplitPane buildSplitPane(boolean borderlessSidebar) {
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        filterScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        filterScrollPane.setMinimumSize(new Dimension(0, 100));
        if (borderlessSidebar) {
            filterScrollPane.setBorder(null);
        }

        JPanel expandedFilterSidebar = new JPanel(new BorderLayout());
        JButton hideFiltersButton = new JButton("Hide Filters");
        hideFiltersButton.setToolTipText("Hide the filter drawer and give the results table more space.");
        expandedFilterSidebar.add(hideFiltersButton, BorderLayout.NORTH);
        expandedFilterSidebar.add(filterScrollPane, BorderLayout.CENTER);

        JPanel collapsedFilterSidebar = new JPanel(new BorderLayout());
        JButton showFiltersButton = new JButton("<html><center>Show<br>Filters</center></html>");
        showFiltersButton.setToolTipText("Show the filter drawer.");
        collapsedFilterSidebar.add(showFiltersButton, BorderLayout.CENTER);

        JPanel filterSidebar = new JPanel(new BorderLayout());
        filterSidebar.add(expandedFilterSidebar, BorderLayout.CENTER);
        hideFiltersButton.addActionListener(event -> {
            filtersCollapsed = true;
            filterSidebar.removeAll();
            filterSidebar.add(collapsedFilterSidebar, BorderLayout.CENTER);
            filterSidebar.setPreferredSize(new Dimension(COLLAPSED_SIDEBAR_WIDTH, 0));
            filterSidebar.revalidate();
            filterSidebar.repaint();
            splitPane.setDividerLocation(COLLAPSED_SIDEBAR_WIDTH);
        });
        showFiltersButton.addActionListener(event -> {
            filtersCollapsed = false;
            filterSidebar.removeAll();
            filterSidebar.add(expandedFilterSidebar, BorderLayout.CENTER);
            filterSidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));
            filterSidebar.revalidate();
            filterSidebar.repaint();
            splitPane.setDividerLocation(SIDEBAR_WIDTH);
        });

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filterSidebar, resultsPanel);
        horizontalSplit.setDividerSize(6);
        horizontalSplit.setResizeWeight(0.0);
        if (borderlessSidebar) {
            horizontalSplit.setBorder(null);
        }
        SwingUtilities.invokeLater(() -> horizontalSplit.setDividerLocation(SIDEBAR_WIDTH));
        return horizontalSplit;
    }

    private void updateFilterStatus() {
        filterPanel.setFilterStatus(
            filterController.statusText(resultsPanel.shownResultsCount(), resultsPanel.allResultsCount())
        );
    }

}
