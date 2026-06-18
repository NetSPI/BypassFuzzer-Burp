package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.session.SessionRegistry;
import com.bypassfuzzer.burp.ui.session.CoverageSweepPanel;

import javax.swing.*;
import java.awt.*;

/**
 * Main UI tab for the BypassFuzzer extension.
 * Uses a tabbed interface to manage multiple fuzzing sessions.
 */
public class BypassFuzzerTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane tabbedPane;
    private final SessionRegistry sessionRegistry;
    private CoverageSweepPanel sweepPanel;

    public BypassFuzzerTab(MontoyaApi api) {
        this.api = api;
        this.tabbedPane = new JTabbedPane();
        this.sessionRegistry = new SessionRegistry(api);
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // Welcome tab
        JPanel welcomePanel = createWelcomePanel();
        tabbedPane.addTab("Welcome", welcomePanel);
        sweepPanel = new CoverageSweepPanel(api);
        tabbedPane.addTab("Sweep", sweepPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(BorderFactory.createEmptyBorder(36, 48, 36, 48));

        JPanel centerPanel = new JPanel(new BorderLayout(0, 24));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        JLabel titleLabel = new JLabel("BypassFuzzer for Burp Suite");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel subtitleLabel = new JLabel("Access Control Bypass Testing Tool");
        subtitleLabel.setFont(new Font("Arial", Font.PLAIN, 16));
        subtitleLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.add(titleLabel);
        headerPanel.add(Box.createVerticalStrut(8));
        headerPanel.add(subtitleLabel);

        JPanel sectionGrid = new JPanel(new GridLayout(0, 2, 24, 18));
        sectionGrid.add(welcomeSection("Targeted testing",
            "1. Right-click a request in Burp\n"
                + "2. Select \"Send to BypassFuzzer\"\n"
                + "3. Select attack types and options\n"
                + "4. Click \"Start Fuzzing\"\n"
                + "5. Review results with filters and highlights"));
        sectionGrid.add(welcomeSection("Sweep",
            "1. Open the Sweep tab\n"
                + "2. Load in-scope Proxy history responses\n"
                + "3. Review and uncheck candidates\n"
                + "4. Preview exact probes\n"
                + "5. Start the bounded broad coverage check"));
        sectionGrid.add(welcomeSection("Targeted playbooks",
            "Header, Path, Verb, Debug Params, Trailing Dot,\n"
                + "Trailing Slash, Extension, Content-Type,\n"
                + "Encoding, Protocol, and Case Variation."));
        sectionGrid.add(welcomeSection("Workflow notes",
            "Sweep is mile-wide and inch-deep.\n"
                + "Targeted request tabs run deeper playbooks.\n"
                + "Use rate limits and auto-throttle for fragile targets.\n"
                + "Send interesting results to Burp tools for follow-up."));

        centerPanel.add(headerPanel, BorderLayout.NORTH);
        centerPanel.add(sectionGrid, BorderLayout.CENTER);
        contentPanel.add(centerPanel, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel welcomeSection(String title, String body) {
        JPanel section = new JPanel(new BorderLayout(0, 8));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(8, 10, 10, 10)
        ));

        JTextArea text = new JTextArea(body);
        text.setEditable(false);
        text.setFocusable(false);
        text.setOpaque(false);
        text.setFont(new Font("Arial", Font.PLAIN, 13));
        text.setLineWrap(true);
        text.setWrapStyleWord(true);
        section.add(text, BorderLayout.CENTER);
        return section;
    }

    /**
     * Load a request into a new fuzzing session tab.
     * Creates a new tab in the tabbed interface for this request.
     *
     * @param request The HTTP request to fuzz
     */
    public void loadRequest(HttpRequest request) {
        FuzzingSessionController sessionController = sessionRegistry.createSession(request);
        FuzzingSessionTab sessionTab = new FuzzingSessionTab(api, sessionController);

        // Add tab with close button
        int tabIndex = tabbedPane.getTabCount();
        tabbedPane.addTab(sessionTab.getTabTitle(), sessionTab);
        tabbedPane.setTabComponentAt(tabIndex, createTabComponent(sessionTab.getTabTitle(), tabIndex));

        // Switch to new tab
        tabbedPane.setSelectedIndex(tabIndex);

        api.logging().logToOutput("New fuzzing session created: " + request.url());
    }

    /**
     * Stop all running fuzzing sessions.
     * Called when extension is unloaded.
     */
    public void cleanup() {
        try {
            api.logging().logToOutput("BypassFuzzer cleanup: stopping all sessions...");
        } catch (Exception e) {
            // API may be unavailable during unload
        }

        for (int index = 0; index < tabbedPane.getTabCount(); index++) {
            Component component = tabbedPane.getComponentAt(index);
            if (component instanceof FuzzingSessionTab sessionTab) {
                sessionTab.cleanup();
            }
        }
        if (sweepPanel != null) {
            sweepPanel.cleanup();
        }

        sessionRegistry.closeAllSessions();

        try {
            api.logging().logToOutput("BypassFuzzer cleanup completed");
        } catch (Exception e) {
            // API may be unavailable during unload
        }
    }

    /**
     * Create a tab component with a close button.
     */
    private JPanel createTabComponent(String title, int tabIndex) {
        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabPanel.setOpaque(false);

        JLabel tabLabel = new JLabel(title);
        tabPanel.add(tabLabel);

        // Close button (only for per-request session tabs)
        if (tabIndex > 1) {
            JButton closeButton = new JButton("×");
            closeButton.setPreferredSize(new Dimension(17, 17));
            closeButton.setMargin(new Insets(0, 0, 0, 0));
            closeButton.setFont(new Font("Arial", Font.BOLD, 12));
            closeButton.setFocusable(false);
            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);

            closeButton.addActionListener(e -> {
                int currentIndex = tabbedPane.indexOfTabComponent(tabPanel);
                if (currentIndex != -1) {
                    int confirm = JOptionPane.showConfirmDialog(
                        api.userInterface().swingUtils().suiteFrame(),
                        "Close this fuzzing session?",
                        "Confirm Close",
                        JOptionPane.YES_NO_OPTION
                    );
                    if (confirm == JOptionPane.YES_OPTION) {
                        Component tabContent = tabbedPane.getComponentAt(currentIndex);
                        if (tabContent instanceof FuzzingSessionTab sessionTab) {
                            sessionTab.cleanup();
                            sessionRegistry.closeSession(sessionTab.getSessionId());
                        }
                        tabbedPane.removeTabAt(currentIndex);
                    }
                }
            });

            tabPanel.add(closeButton);
        }

        return tabPanel;
    }
}
