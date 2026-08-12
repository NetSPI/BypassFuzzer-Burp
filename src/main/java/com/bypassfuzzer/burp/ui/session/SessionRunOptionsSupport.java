package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.session.SessionRunOptions;

/**
 * Shared collection logic for attack-selection and run-options panels.
 */
public final class SessionRunOptionsSupport {

    private SessionRunOptionsSupport() {
    }

    public static SessionRunOptions collect(AttackSelectionPanel attackSelectionPanel, RunOptionsPanel runOptionsPanel) {
        int concurrency;
        try {
            concurrency = Math.max(1, Integer.parseInt(runOptionsPanel.concurrencyText().trim()));
        } catch (NumberFormatException e) {
            concurrency = 1;
        }
        int requestDelayMs;
        try {
            requestDelayMs = Math.max(0, Integer.parseInt(runOptionsPanel.requestDelayText().trim()));
        } catch (NumberFormatException e) {
            requestDelayMs = 0;
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
            0,
            requestDelayMs,
            concurrency,
            SessionInputParsers.parseStatusCodes(runOptionsPanel.throttleStatusCodesText()),
            runOptionsPanel.isAutoThrottleEnabled(),
            runOptionsPanel.requestHeaders()
        );
    }
}
