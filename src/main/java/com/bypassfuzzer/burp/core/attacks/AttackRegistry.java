package com.bypassfuzzer.burp.core.attacks;

import com.bypassfuzzer.burp.config.FuzzerConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Central registry for attack ordering and construction.
 */
public class AttackRegistry {

    public List<RegisteredAttack> buildEnabledAttacks(FuzzerConfig config, String targetUrl) {
        Set<AttackType> enabled = config.getEnabledAttackTypes();
        List<RegisteredAttack> attacks = new ArrayList<>();

        register(attacks, enabled, AttackType.HEADER,
            new HeaderAttack(targetUrl, config.getOobPayload(), config.isEnableCollaboratorPayloads()));
        register(attacks, enabled, AttackType.PATH, new PathAttack(targetUrl));
        register(attacks, enabled, AttackType.VERB, new VerbAttack());
        register(attacks, enabled, AttackType.PARAM, new ParamAttack());
        register(attacks, enabled, AttackType.COOKIE, new CookieParamAttack(config.isEnableFuzzExistingCookies()));
        register(attacks, enabled, AttackType.TRAILING_DOT, new TrailingDotAttack());
        register(attacks, enabled, AttackType.TRAILING_SLASH, new TrailingSlashAttack());
        register(attacks, enabled, AttackType.EXTENSION, new ExtensionAttack(targetUrl));
        register(attacks, enabled, AttackType.CONTENT_TYPE, new ContentTypeAttack());
        register(attacks, enabled, AttackType.ENCODING, new EncodingAttack());
        register(attacks, enabled, AttackType.PROTOCOL, new ProtocolAttack());
        register(attacks, enabled, AttackType.CASE, new CaseAttack());

        return attacks;
    }

    private void register(List<RegisteredAttack> attacks, Set<AttackType> enabled, AttackType type, AttackStrategy strategy) {
        if (enabled.contains(type)) {
            attacks.add(new RegisteredAttack(type, strategy));
        }
    }
}
