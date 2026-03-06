package com.bypassfuzzer.burp.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionRunOptionsTest {

    @Test
    void exposesEnabledAttackTypesAndAppliesThemToConfig() {
        SessionRunOptions options = new SessionRunOptions(
            true, false, true, false, false, true, false, true, false, true, false,
            true, false, true, 7, Set.of(429, 503)
        );

        assertEquals(Set.of(
            AttackType.HEADER,
            AttackType.VERB,
            AttackType.TRAILING_SLASH,
            AttackType.CONTENT_TYPE,
            AttackType.PROTOCOL
        ), options.enabledAttackTypes());

        FuzzerConfig config = new FuzzerConfig();
        options.applyTo(config);

        assertTrue(config.isEnableHeaderAttack());
        assertFalse(config.isEnablePathAttack());
        assertTrue(config.isEnableVerbAttack());
        assertTrue(config.isEnableTrailingSlashAttack());
        assertTrue(config.isEnableContentTypeAttack());
        assertTrue(config.isEnableProtocolAttack());
        assertTrue(config.isEnableCollaboratorPayloads());
        assertTrue(config.isEnableFuzzExistingCookies());
        assertEquals(7, config.getRequestsPerSecond());
        assertEquals(Set.of(429, 503), config.getThrottleStatusCodes());
    }
}
