package com.bypassfuzzer.burp.core.attacks;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AttackRegistryTest {

    @Test
    void buildsEnabledAttacksInStableOrder() {
        FuzzerConfig config = new FuzzerConfig();
        config.setEnableHeaderAttack(false);
        config.setEnableVerbAttack(false);
        config.setEnableCookieParamAttack(false);
        config.setEnableTrailingDotAttack(false);
        config.setEnableTrailingSlashAttack(false);
        config.setEnableExtensionAttack(false);
        config.setEnableContentTypeAttack(false);
        config.setEnableEncodingAttack(false);
        config.setEnableProtocolAttack(false);

        AttackRegistry registry = new AttackRegistry();
        List<AttackType> attackTypes = registry.buildEnabledAttacks(config, "https://example.com/admin").stream()
            .map(RegisteredAttack::type)
            .toList();

        assertEquals(List.of(AttackType.PATH, AttackType.PARAM, AttackType.CASE), attackTypes);
    }
}
