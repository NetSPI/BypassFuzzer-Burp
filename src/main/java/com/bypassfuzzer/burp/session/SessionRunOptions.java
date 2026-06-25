package com.bypassfuzzer.burp.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackType;

import java.util.EnumSet;
import java.util.Set;

public record SessionRunOptions(
    boolean headerAttack,
    boolean pathAttack,
    boolean verbAttack,
    boolean paramAttack,
    boolean trailingDotAttack,
    boolean trailingSlashAttack,
    boolean extensionAttack,
    boolean contentTypeAttack,
    boolean encodingAttack,
    boolean protocolAttack,
    boolean caseAttack,
    boolean collaboratorPayloads,
    boolean cookieParamAttack,
    boolean fuzzExistingCookies,
    int requestsPerSecond,
    int concurrency,
    Set<Integer> throttleStatusCodes
) {

    public Set<AttackType> enabledAttackTypes() {
        Set<AttackType> types = EnumSet.noneOf(AttackType.class);
        if (headerAttack) types.add(AttackType.HEADER);
        if (pathAttack) types.add(AttackType.PATH);
        if (verbAttack) types.add(AttackType.VERB);
        if (paramAttack) types.add(AttackType.PARAM);
        if (trailingDotAttack) types.add(AttackType.TRAILING_DOT);
        if (trailingSlashAttack) types.add(AttackType.TRAILING_SLASH);
        if (extensionAttack) types.add(AttackType.EXTENSION);
        if (contentTypeAttack) types.add(AttackType.CONTENT_TYPE);
        if (encodingAttack) types.add(AttackType.ENCODING);
        if (protocolAttack) types.add(AttackType.PROTOCOL);
        if (caseAttack) types.add(AttackType.CASE);
        if (cookieParamAttack) types.add(AttackType.COOKIE);
        return types;
    }

    public boolean hasEnabledAttacks() {
        return !enabledAttackTypes().isEmpty();
    }

    public SessionRunOptions withoutCollaboratorPayloads() {
        return new SessionRunOptions(
            headerAttack,
            pathAttack,
            verbAttack,
            paramAttack,
            trailingDotAttack,
            trailingSlashAttack,
            extensionAttack,
            contentTypeAttack,
            encodingAttack,
            protocolAttack,
            caseAttack,
            false,
            cookieParamAttack,
            fuzzExistingCookies,
            requestsPerSecond,
            concurrency,
            throttleStatusCodes
        );
    }

    public void applyTo(FuzzerConfig config) {
        config.setEnableHeaderAttack(headerAttack);
        config.setEnablePathAttack(pathAttack);
        config.setEnableVerbAttack(verbAttack);
        config.setEnableParamAttack(paramAttack);
        config.setEnableTrailingDotAttack(trailingDotAttack);
        config.setEnableTrailingSlashAttack(trailingSlashAttack);
        config.setEnableExtensionAttack(extensionAttack);
        config.setEnableContentTypeAttack(contentTypeAttack);
        config.setEnableEncodingAttack(encodingAttack);
        config.setEnableProtocolAttack(protocolAttack);
        config.setEnableCaseAttack(caseAttack);
        config.setEnableCollaboratorPayloads(collaboratorPayloads);
        config.setEnableCookieParamAttack(cookieParamAttack);
        config.setEnableFuzzExistingCookies(fuzzExistingCookies);
        config.setRequestsPerSecond(requestsPerSecond);
        config.setConcurrency(concurrency);
        config.setThrottleStatusCodes(throttleStatusCodes);
        config.setEnableAutoThrottle(!throttleStatusCodes.isEmpty());
    }
}
