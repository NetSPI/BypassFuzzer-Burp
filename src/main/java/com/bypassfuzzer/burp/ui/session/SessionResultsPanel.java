package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultHighlighter;
import com.bypassfuzzer.burp.ui.FuzzerResultsTableModel;

import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;

/**
 * Owns the results table, highlight popup, and Burp request/response viewers.
 */
public class SessionResultsPanel extends JPanel {

    public enum ViewerLayout {
        BELOW_TABLE,
        RIGHT_OF_TABLE
    }

    public enum TableLayout {
        DEFAULT,
        URL_VALIDATION
    }

    private final ResultHighlighter highlighter;
    private final Runnable filterRefreshListener;
    private final FuzzerResultsTableModel tableModel;
    private final JTable resultsTable;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private JPopupMenu tablePopupMenu;
    private AttackResult displayedResult;

    private final ViewerLayout viewerLayout;
    private final TableLayout tableLayout;

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener) {
        this(api, highlighter, filterRefreshListener, ViewerLayout.BELOW_TABLE, TableLayout.DEFAULT);
    }

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener, ViewerLayout viewerLayout) {
        this(api, highlighter, filterRefreshListener, viewerLayout, TableLayout.DEFAULT);
    }

    public SessionResultsPanel(MontoyaApi api, ResultHighlighter highlighter, Runnable filterRefreshListener,
                               ViewerLayout viewerLayout, TableLayout tableLayout) {
        super(new BorderLayout());
        this.highlighter = highlighter;
        this.filterRefreshListener = filterRefreshListener;
        this.viewerLayout = viewerLayout == null ? ViewerLayout.BELOW_TABLE : viewerLayout;
        this.tableLayout = tableLayout == null ? TableLayout.DEFAULT : tableLayout;
        this.tableModel = new FuzzerResultsTableModel(toModelLayout(this.tableLayout));
        this.resultsTable = new JTable(tableModel);
        this.requestViewer = api.userInterface().createHttpRequestEditor();
        this.responseViewer = api.userInterface().createHttpResponseEditor();
        initializeUi();
    }

    public void addResult(AttackResult result, boolean passesFilter) {
        tableModel.addResult(result, passesFilter);
    }

    public void applyFilter(Predicate<AttackResult> filter) {
        List<? extends javax.swing.RowSorter.SortKey> savedSortKeys = null;
        if (resultsTable.getRowSorter() != null) {
            savedSortKeys = new ArrayList<>(resultsTable.getRowSorter().getSortKeys());
        }

        tableModel.applyFilter(filter);
        initializeRowSorter();

        if (savedSortKeys != null && !savedSortKeys.isEmpty() && resultsTable.getRowSorter() != null) {
            try {
                resultsTable.getRowSorter().setSortKeys(savedSortKeys);
            } catch (Exception e) {
                // Ignore invalid sort state.
            }
        }

        resultsTable.repaint();
    }

    public void clear() {
        tableModel.clear();
        displayedResult = null;
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
    }

    public int shownResultsCount() {
        return tableModel.getRowCount();
    }

    public int allResultsCount() {
        return tableModel.getAllResultsCount();
    }

    private void initializeUi() {
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        initializeRowSorter();
        configureRenderer();
        configureSelection();
        createTablePopupMenu();
        configurePopupHandling();
        configureColumns();

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Request", requestViewer.uiComponent());
        viewerTabs.addTab("Response", responseViewer.uiComponent());

        int splitOrientation = viewerLayout == ViewerLayout.RIGHT_OF_TABLE
            ? JSplitPane.HORIZONTAL_SPLIT
            : JSplitPane.VERTICAL_SPLIT;
        JSplitPane splitPane = new JSplitPane(splitOrientation, tableScrollPane, viewerTabs);
        splitPane.setResizeWeight(0.5);
        if (viewerLayout == ViewerLayout.RIGHT_OF_TABLE) {
            SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
        } else {
            SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
        }
        add(splitPane, BorderLayout.CENTER);
    }

    private void configureRenderer() {
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.LEFT);

                if (!isSelected) {
                    AttackResult result = tableModel.getResult(table.convertRowIndexToModel(row));
                    Color rowColor = result == null ? null : highlighter.colorFor(result);
                    component.setBackground(rowColor != null ? rowColor : table.getBackground());
                    component.setForeground(table.getForeground());
                }

                return component;
            }
        });
    }

    private void configureSelection() {
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showResultDetails(resultsTable.convertRowIndexToModel(selectedRow));
                }
            }
        });
    }

    private void configureColumns() {
        if (tableLayout == TableLayout.URL_VALIDATION) {
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
            resultsTable.getColumnModel().getColumn(0).setMaxWidth(50);
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(120);
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(90);
            resultsTable.getColumnModel().getColumn(2).setMaxWidth(120);
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(90);
            resultsTable.getColumnModel().getColumn(3).setMaxWidth(120);
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(280);
            resultsTable.getColumnModel().getColumn(5).setPreferredWidth(60);
            resultsTable.getColumnModel().getColumn(5).setMaxWidth(80);
            resultsTable.getColumnModel().getColumn(6).setPreferredWidth(80);
            resultsTable.getColumnModel().getColumn(7).setPreferredWidth(130);
            return;
        }

        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(0).setMaxWidth(50);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(1).setMaxWidth(80);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(300);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(150);
    }

    private void initializeRowSorter() {
        TableRowSorter<FuzzerResultsTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(0, Comparator.comparingInt(o -> (Integer) o));
        if (tableLayout == TableLayout.URL_VALIDATION) {
            sorter.setComparator(5, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(6, Comparator.comparingInt(o -> (Integer) o));
        } else {
            sorter.setComparator(3, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
        }
        sorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
        resultsTable.setRowSorter(sorter);
    }

    private void showResultDetails(int modelRow) {
        AttackResult result = tableModel.getResult(modelRow);
        if (result == null) {
            return;
        }

        if (result == displayedResult) {
            return;
        }
        displayedResult = result;

        if (result.getRequest() != null) {
            requestViewer.setRequest(result.getRequest());
        }
        if (result.getResponse() != null) {
            responseViewer.setResponse(result.getResponse());
        }
    }

    private void createTablePopupMenu() {
        tablePopupMenu = new JPopupMenu();
        highlighter.namedColors().forEach((name, color) -> {
            JMenuItem item = new JMenuItem("Highlight " + name);
            item.addActionListener(e -> updateHighlight(color, false));
            tablePopupMenu.add(item);
        });

        tablePopupMenu.addSeparator();
        JMenuItem clearItem = new JMenuItem("Clear Highlight");
        clearItem.addActionListener(e -> updateHighlight(null, true));
        tablePopupMenu.add(clearItem);
    }

    private void configurePopupHandling() {
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent event) {
                if (!event.isPopupTrigger()) {
                    return;
                }

                int row = resultsTable.rowAtPoint(event.getPoint());
                if (row >= 0) {
                    resultsTable.setRowSelectionInterval(row, row);
                    tablePopupMenu.show(event.getComponent(), event.getX(), event.getY());
                }
            }
        });
    }

    private void updateHighlight(Color color, boolean clear) {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
        AttackResult result = tableModel.getResult(modelRow);
        if (result == null) {
            return;
        }

        if (clear) {
            highlighter.clear(result);
        } else {
            highlighter.highlight(result, color);
        }

        SwingUtilities.invokeLater(() -> {
            resultsTable.repaint();
            filterRefreshListener.run();
        });
    }

    private FuzzerResultsTableModel.TableLayout toModelLayout(TableLayout tableLayout) {
        return tableLayout == TableLayout.URL_VALIDATION
            ? FuzzerResultsTableModel.TableLayout.URL_VALIDATION
            : FuzzerResultsTableModel.TableLayout.DEFAULT;
    }
}
