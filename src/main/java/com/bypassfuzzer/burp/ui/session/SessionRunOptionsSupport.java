package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.session.SessionRunOptions;

/**
 * Shared collection logic for attack-selection and run-options panels.
 */
public final class SessionRunOptionsSupport {

    private SessionRunOptionsSupport() {
    }

    public static SessionRunOptions collect(AttackSelectionPanel attackSelectionPanel, RunOptionsPanel runOptionsPanel) {
        int requestsPerSecond;
        try {
            requestsPerSecond = Math.max(0, Integer.parseInt(runOptionsPanel.requestsPerSecondText().trim()));
        } catch (NumberFormatException e) {
            requestsPerSecond = 0;
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
            requestsPerSecond,
            SessionInputParsers.parseStatusCodes(runOptionsPanel.throttleStatusCodesText())
        );
    }
}
