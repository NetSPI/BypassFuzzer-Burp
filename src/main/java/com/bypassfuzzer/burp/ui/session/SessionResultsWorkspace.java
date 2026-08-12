package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingWorker;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
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
    private final RequestSender retrySender;
    private final JButton retryThrottledButton;
    private final JLabel retryStatusLabel;
    private final Map<String, DeferredRetry> throttledRetries = new LinkedHashMap<>();
    private Set<Integer> throttleStatusCodes = Set.of(429, 503);
    private int retryRequestsPerSecond;
    private int retryDelayMs;
    private boolean retryAutoThrottleEnabled = true;
    private boolean primaryRunActive;
    private boolean retryRunning;
    private long queueGeneration;
    private SwingWorker<Void, RetryOutcome> retryWorker;
    private boolean filtersCollapsed;

    public SessionResultsWorkspace(MontoyaApi api,
                                   Consumer<String> errorLogger,
                                   Consumer<SessionResultsWorkspace> filterAppliedListener,
                                   SessionResultsPanel.ViewerLayout viewerLayout,
                                   SessionResultsPanel.TableLayout tableLayout,
                                   boolean borderlessSidebar) {
        this(api, errorLogger, filterAppliedListener, viewerLayout, tableLayout, borderlessSidebar,
            new MontoyaRequestSender(api));
    }

    SessionResultsWorkspace(MontoyaApi api,
                            Consumer<String> errorLogger,
                            Consumer<SessionResultsWorkspace> filterAppliedListener,
                            SessionResultsPanel.ViewerLayout viewerLayout,
                            SessionResultsPanel.TableLayout tableLayout,
                            boolean borderlessSidebar,
                            RequestSender retrySender) {
        this.filterAppliedListener = filterAppliedListener == null ? workspace -> { } : filterAppliedListener;
        this.retrySender = retrySender;
        this.filterPanel = new FilterPanel(filterController.filterConfig(), errorLogger);
        this.filterPanel.setFilterChangeListener(this::applyFilters);
        this.resultsPanel = new SessionResultsPanel(api, filterController.highlighter(), this::applyFilters, viewerLayout, tableLayout);
        this.retryThrottledButton = new JButton("Retry Throttled (0)");
        this.retryThrottledButton.setEnabled(false);
        this.retryThrottledButton.setToolTipText(
            "Retry deferred throttled requests serially. Unsafe methods require confirmation.");
        this.retryThrottledButton.addActionListener(event -> retryThrottledFromButton());
        this.retryStatusLabel = new JLabel("");
        this.splitPane = buildSplitPane(borderlessSidebar);
        updateFilterStatus();
        updateRetryControls();
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
        trackThrottleResult(result);
        updateFilterStatus();
    }

    public void clear() {
        cancelRetryWorker();
        synchronized (throttledRetries) {
            throttledRetries.clear();
            queueGeneration++;
        }
        resultsPanel.clear();
        filterController.reset();
        updateFilterStatus();
        retryStatusLabel.setText("");
        updateRetryControls();
    }

    public void cleanup() {
        cancelRetryWorker();
    }

    public void configureThrottleRetries(Set<Integer> statusCodes, int requestsPerSecond, int requestDelayMs) {
        configureThrottleRetries(statusCodes, requestsPerSecond, requestDelayMs,
            statusCodes != null && !statusCodes.isEmpty());
    }

    public void configureThrottleRetries(Set<Integer> statusCodes, int requestsPerSecond,
                                         int requestDelayMs, boolean autoThrottleEnabled) {
        throttleStatusCodes = statusCodes == null ? Set.of() : Set.copyOf(statusCodes);
        retryRequestsPerSecond = Math.max(0, requestsPerSecond);
        retryDelayMs = Math.max(0, requestDelayMs);
        retryAutoThrottleEnabled = autoThrottleEnabled;
        updateRetryControls();
    }

    public void setPrimaryRunActive(boolean active) {
        primaryRunActive = active;
        updateRetryControls();
    }

    public int throttledRetryCount() {
        synchronized (throttledRetries) {
            return throttledRetries.size();
        }
    }

    public boolean isRetryRunning() {
        return retryRunning;
    }

    void retryThrottled(boolean includeUnsafeMethods) {
        List<Map.Entry<String, DeferredRetry>> selected = new ArrayList<>();
        long generation;
        synchronized (throttledRetries) {
            if (retryRunning || primaryRunActive) {
                return;
            }
            for (Map.Entry<String, DeferredRetry> entry : throttledRetries.entrySet()) {
                if (includeUnsafeMethods || isSafeMethod(entry.getValue().result().getRequest())) {
                    selected.add(Map.entry(entry.getKey(), entry.getValue()));
                }
            }
            if (selected.isEmpty()) {
                return;
            }
            selected.forEach(entry -> throttledRetries.remove(entry.getKey()));
            generation = queueGeneration;
            retryRunning = true;
        }

        retryStatusLabel.setText("Retrying " + selected.size() + " throttled request(s) serially...");
        updateRetryControls();
        RateLimiter rateLimiter = new RateLimiter(null, retryRequestsPerSecond, retryDelayMs,
            throttleStatusCodes, retryAutoThrottleEnabled);
        retryWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                for (Map.Entry<String, DeferredRetry> queued : selected) {
                    if (isCancelled() || Thread.currentThread().isInterrupted()) {
                        break;
                    }
                    DeferredRetry retry = queued.getValue();
                    rateLimiter.reportResponse(retry.result().getResponse());
                    if (!rateLimiter.waitBeforeRequest()) {
                        break;
                    }
                    HttpResponse response = sendRetry(retry.result().getRequest());
                    rateLimiter.reportResponse(response);
                    publish(new RetryOutcome(queued.getKey(), retry, response, generation));
                }
                return null;
            }

            @Override
            protected void process(List<RetryOutcome> outcomes) {
                for (RetryOutcome outcome : outcomes) {
                    if (outcome.generation() != queueGeneration) {
                        continue;
                    }
                    int attempt = outcome.retry().result().getThrottleRetryAttempt() + 1;
                    AttackResult retryResult = AttackResult.throttleRetryOf(
                        outcome.retry().result(), outcome.response(), attempt);
                    addResult(retryResult);
                }
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (CancellationException ignored) {
                } catch (Exception ignored) {
                } finally {
                    synchronized (throttledRetries) {
                        if (retryWorker != this) {
                            return;
                        }
                        retryRunning = false;
                        retryWorker = null;
                    }
                    int remaining = throttledRetryCount();
                    retryStatusLabel.setText(remaining == 0
                        ? "Throttle retry pass completed; no requests remain throttled."
                        : "Throttle retry pass completed; " + remaining + " request(s) remain throttled.");
                    updateRetryControls();
                }
            }
        };
        retryWorker.execute();
    }

    public int shownResultsCount() {
        return resultsPanel.shownResultsCount();
    }

    public int allResultsCount() {
        return resultsPanel.allResultsCount();
    }

    public List<AttackResult> allResults() {
        return resultsPanel.allResults();
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

        JPanel resultsContainer = new JPanel(new BorderLayout());
        JPanel retryRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        retryRow.add(retryThrottledButton);
        retryRow.add(retryStatusLabel);
        resultsContainer.add(retryRow, BorderLayout.NORTH);
        resultsContainer.add(resultsPanel, BorderLayout.CENTER);

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filterSidebar, resultsContainer);
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

    private void retryThrottledFromButton() {
        int unsafeCount;
        synchronized (throttledRetries) {
            unsafeCount = (int) throttledRetries.values().stream()
                .filter(retry -> !isSafeMethod(retry.result().getRequest()))
                .count();
        }
        boolean includeUnsafe = false;
        if (unsafeCount > 0 && !GraphicsEnvironment.isHeadless()) {
            Object[] choices = {"Retry safe only", "Include unsafe", "Cancel"};
            int choice = JOptionPane.showOptionDialog(
                splitPane,
                unsafeCount + " queued request(s) use state-changing methods.\n"
                    + "Choose whether this pass should resend them.",
                "Retry Throttled Requests",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                choices,
                choices[0]
            );
            if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) {
                return;
            }
            includeUnsafe = choice == 1;
        }
        retryThrottled(includeUnsafe);
    }

    private void trackThrottleResult(AttackResult result) {
        if (result == null || result.getRequest() == null || result.getResponse() == null
            || !throttleStatusCodes.contains(result.getStatusCode())) {
            return;
        }
        synchronized (throttledRetries) {
            throttledRetries.put(retryKey(result), new DeferredRetry(result));
        }
        updateRetryControls();
    }

    private String retryKey(AttackResult result) {
        HttpRequest request = result.getRequest();
        StringBuilder key = new StringBuilder();
        key.append(result.getAttackType()).append('\u0000')
            .append(result.getPayload()).append('\u0000')
            .append(result.getTargetLabel()).append('\u0000')
            .append(result.getPayloadFamily()).append('\u0000');
        try {
            HttpService service = request.httpService();
            if (service != null) {
                key.append(service.secure()).append(':').append(service.host()).append(':').append(service.port());
            }
            key.append('\u0000').append(request.toString());
        } catch (Exception e) {
            key.append(System.identityHashCode(request));
        }
        return key.toString();
    }

    private boolean isSafeMethod(HttpRequest request) {
        if (request == null || request.method() == null) {
            return false;
        }
        String method = request.method().toUpperCase(Locale.ROOT);
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
    }

    private HttpResponse sendRetry(HttpRequest request) {
        HttpMode mode = requestMode(request);
        return mode == null
            ? retrySender.send(request, 30, TimeUnit.SECONDS)
            : retrySender.send(request, mode, 30, TimeUnit.SECONDS);
    }

    private HttpMode requestMode(HttpRequest request) {
        try {
            String version = request.httpVersion();
            if (version == null) {
                return null;
            }
            if (version.contains("2")) {
                return HttpMode.HTTP_2;
            }
            if (version.contains("1")) {
                return HttpMode.HTTP_1;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void cancelRetryWorker() {
        SwingWorker<Void, RetryOutcome> worker = retryWorker;
        retryWorker = null;
        retryRunning = false;
        if (worker != null) {
            worker.cancel(true);
        }
    }

    private void updateRetryControls() {
        Runnable update = () -> {
            int count = throttledRetryCount();
            retryThrottledButton.setText("Retry Throttled (" + count + ")");
            retryThrottledButton.setEnabled(count > 0 && !primaryRunActive && !retryRunning);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    private record DeferredRetry(AttackResult result) {
    }

    private record RetryOutcome(String key, DeferredRetry retry, HttpResponse response, long generation) {
    }

}
