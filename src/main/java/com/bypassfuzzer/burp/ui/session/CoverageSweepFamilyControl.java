package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepFamilySelection;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPayloadSet;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Window;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/** Dialog-backed selector for the payload families used by each Sweep inventory. */
final class CoverageSweepFamilyControl {

    private final Component owner;
    private final Supplier<CoverageSweepPayloadSet> payloadSetSupplier;
    private final Runnable onChange;
    private final JButton button = new JButton("Payload Families...");
    private final Map<String, JCheckBox> highSignalBoxes = new LinkedHashMap<>();
    private final Map<AttackType, JCheckBox> bypassBoxes = new EnumMap<>(AttackType.class);
    private JDialog dialog;
    private JTabbedPane tabs;

    CoverageSweepFamilyControl(Component owner,
                               Supplier<CoverageSweepPayloadSet> payloadSetSupplier,
                               Runnable onChange) {
        this.owner = owner;
        this.payloadSetSupplier = payloadSetSupplier;
        this.onChange = onChange == null ? () -> { } : onChange;

        CoverageSweepFamilySelection.HIGH_SIGNAL_FAMILIES.forEach(family ->
            highSignalBoxes.put(family, createCheckBox(family)));
        for (AttackType attackType : AttackType.values()) {
            bypassBoxes.put(attackType, createCheckBox(attackType.displayName()));
        }

        button.setToolTipText("Choose which High Signal categories and full Bypass attack families Sweep may send.");
        button.addActionListener(event -> openDialog());
    }

    JButton button() {
        return button;
    }

    void setEnabled(boolean enabled) {
        button.setEnabled(enabled);
        highSignalBoxes.values().forEach(box -> box.setEnabled(enabled));
        bypassBoxes.values().forEach(box -> box.setEnabled(enabled));
    }

    CoverageSweepFamilySelection selection() {
        Set<String> highSignal = new LinkedHashSet<>();
        highSignalBoxes.forEach((family, box) -> {
            if (box.isSelected()) {
                highSignal.add(family);
            }
        });

        Set<AttackType> bypass = new LinkedHashSet<>();
        bypassBoxes.forEach((family, box) -> {
            if (box.isSelected()) {
                bypass.add(family);
            }
        });
        return new CoverageSweepFamilySelection(highSignal, bypass);
    }

    void setHighSignalFamilyEnabled(String family, boolean enabled) {
        JCheckBox box = highSignalBoxes.get(family);
        if (box != null) {
            box.setSelected(enabled);
            onChange.run();
        }
    }

    void setBypassFamilyEnabled(AttackType family, boolean enabled) {
        JCheckBox box = bypassBoxes.get(family);
        if (box != null) {
            box.setSelected(enabled);
            onChange.run();
        }
    }

    private JCheckBox createCheckBox(String label) {
        JCheckBox checkBox = new JCheckBox(label, true);
        checkBox.addActionListener(event -> onChange.run());
        return checkBox;
    }

    private void openDialog() {
        if (dialog == null) {
            Window window = SwingUtilities.getWindowAncestor(owner);
            dialog = new JDialog(window, "Sweep Payload Families", Dialog.ModalityType.MODELESS);
            dialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            dialog.setContentPane(buildDialogContent());
            dialog.setSize(new Dimension(700, 520));
            dialog.setMinimumSize(new Dimension(560, 400));
        }
        tabs.setSelectedIndex(payloadSetSupplier.get() == CoverageSweepPayloadSet.ALL_PAYLOADS ? 1 : 0);
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private JPanel buildDialogContent() {
        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel description = new JLabel(
            "Selections are saved independently for High Signal and All Bypass Families modes.");
        content.add(description, BorderLayout.NORTH);

        tabs = new JTabbedPane();
        tabs.addTab("High Signal", familyTab(highSignalBoxes));
        tabs.addTab("All Bypass Families", familyTab(bypassBoxes));
        content.add(tabs, BorderLayout.CENTER);

        JButton close = new JButton("Close");
        close.addActionListener(event -> dialog.setVisible(false));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(close);
        content.add(buttons, BorderLayout.SOUTH);
        return content;
    }

    private JPanel familyTab(Map<?, JCheckBox> boxes) {
        JPanel wrapper = new JPanel(new BorderLayout(4, 4));
        JPanel choices = new JPanel(new GridLayout(0, 2, 8, 4));
        boxes.values().forEach(choices::add);

        JButton checkAll = new JButton("Check All");
        checkAll.addActionListener(event -> setAll(boxes, true));
        JButton uncheckAll = new JButton("Uncheck All");
        uncheckAll.addActionListener(event -> setAll(boxes, false));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(checkAll);
        actions.add(uncheckAll);

        JPanel vertical = new JPanel();
        vertical.setLayout(new BoxLayout(vertical, BoxLayout.Y_AXIS));
        vertical.add(choices);
        vertical.add(actions);
        JScrollPane scrollPane = new JScrollPane(vertical);
        scrollPane.setBorder(null);
        wrapper.add(scrollPane, BorderLayout.CENTER);
        return wrapper;
    }

    private void setAll(Map<?, JCheckBox> boxes, boolean selected) {
        boxes.values().forEach(box -> box.setSelected(selected));
        onChange.run();
    }
}
