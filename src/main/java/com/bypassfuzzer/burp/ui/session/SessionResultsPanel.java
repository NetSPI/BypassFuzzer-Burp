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
import java.awt.Font;
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

    private static final Color IDOR_CONTROL_BADGE = new Color(46, 86, 132);
    private static final Color IDOR_BASELINE_BADGE = new Color(122, 88, 32);
    private static final Color IDOR_SUCCESS = new Color(108, 214, 152);
    private static final Color IDOR_REDIRECT = new Color(104, 182, 255);
    private static final Color IDOR_CLIENT_ERROR = new Color(236, 183, 79);
    private static final Color IDOR_SERVER_ERROR = new Color(229, 116, 116);
    private static final Color IDOR_PLAYBOOK = new Color(190, 214, 255);

    public enum ViewerLayout {
        BELOW_TABLE,
        RIGHT_OF_TABLE
    }

    public enum TableLayout {
        DEFAULT,
        IDOR,
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
                setFont(table.getFont());

                AttackResult result = tableModel.getResult(table.convertRowIndexToModel(row));
                if (!isSelected) {
                    Color rowColor = result == null ? null : highlighter.colorFor(result);
                    component.setBackground(rowColor != null ? rowColor : table.getBackground());
                    component.setForeground(table.getForeground());
                }

                if (tableLayout == TableLayout.IDOR && result != null) {
                    applyIdorCellStyling(table, component, value, column, isSelected, result);
                } else if (column == 3 || column == 4 || column == 5 || column == 6) {
                    setHorizontalAlignment(SwingConstants.CENTER);
                }

                return component;
            }
        });
    }

    private void applyIdorCellStyling(JTable table,
                                      Component component,
                                      Object value,
                                      int column,
                                      boolean isSelected,
                                      AttackResult result) {
        if (!(component instanceof DefaultTableCellRenderer renderer)) {
            return;
        }

        if (column == 1) {
            renderer.setHorizontalAlignment(SwingConstants.CENTER);
            renderer.setFont(table.getFont().deriveFont(Font.BOLD));

            if (!isSelected) {
                String group = result.getTargetLabel();
                if ("Control".equals(group)) {
                    component.setBackground(IDOR_CONTROL_BADGE);
                } else if ("Baseline".equals(group)) {
                    component.setBackground(IDOR_BASELINE_BADGE);
                }
            }
            return;
        }

        if (column == 2) {
            renderer.setFont(new Font(Font.MONOSPACED, table.getFont().getStyle(), table.getFont().getSize() - 1));
            if (!isSelected) {
                component.setForeground(IDOR_PLAYBOOK);
            }
            return;
        }

        if (column == 4) {
            renderer.setHorizontalAlignment(SwingConstants.CENTER);
            renderer.setFont(table.getFont().deriveFont(Font.BOLD));
            if (!isSelected && value instanceof Integer status) {
                component.setForeground(statusColor(status));
            }
            return;
        }

        if (column == 5) {
            renderer.setHorizontalAlignment(SwingConstants.RIGHT);
            return;
        }

        if (column == 6) {
            renderer.setHorizontalAlignment(SwingConstants.LEFT);
        }
    }

    private Color statusColor(int status) {
        if (status >= 200 && status < 300) {
            return IDOR_SUCCESS;
        }
        if (status >= 300 && status < 400) {
            return IDOR_REDIRECT;
        }
        if (status >= 400 && status < 500) {
            return IDOR_CLIENT_ERROR;
        }
        if (status >= 500) {
            return IDOR_SERVER_ERROR;
        }
        return resultsTable.getForeground();
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

        if (tableLayout == TableLayout.IDOR) {
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(34);
            resultsTable.getColumnModel().getColumn(0).setMaxWidth(52);
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(88);
            resultsTable.getColumnModel().getColumn(1).setMaxWidth(110);
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(210);
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(420);
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(64);
            resultsTable.getColumnModel().getColumn(4).setMaxWidth(84);
            resultsTable.getColumnModel().getColumn(5).setPreferredWidth(86);
            resultsTable.getColumnModel().getColumn(5).setMaxWidth(110);
            resultsTable.getColumnModel().getColumn(6).setPreferredWidth(170);
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
        } else if (tableLayout == TableLayout.IDOR) {
            sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
            sorter.setComparator(5, Comparator.comparingInt(o -> (Integer) o));
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
        return switch (tableLayout) {
            case URL_VALIDATION -> FuzzerResultsTableModel.TableLayout.URL_VALIDATION;
            case IDOR -> FuzzerResultsTableModel.TableLayout.IDOR;
            case DEFAULT -> FuzzerResultsTableModel.TableLayout.DEFAULT;
        };
    }
}
