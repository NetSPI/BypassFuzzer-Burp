package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import java.awt.Dimension;
import java.util.function.Consumer;

/**
 * Shared filter/results workspace used by session tabs.
 */
public class SessionResultsWorkspace {

    private static final int SIDEBAR_WIDTH = 500;

    private final ResultFilterController filterController = new ResultFilterController();
    private final FilterPanel filterPanel;
    private final SessionResultsPanel resultsPanel;
    private final JSplitPane splitPane;
    private final Consumer<SessionResultsWorkspace> filterAppliedListener;

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

    private JSplitPane buildSplitPane(boolean borderlessSidebar) {
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        filterScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        filterScrollPane.setMinimumSize(new Dimension(250, 100));
        if (borderlessSidebar) {
            filterScrollPane.setBorder(null);
        }

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filterScrollPane, resultsPanel);
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
