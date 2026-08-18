package com.bypassfuzzer.burp.core.coverage;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

/** A serialized or deferred retry request that retains its exact probe context. */
public record CoverageSweepRetryItem(AttackResult result, CoverageSweepProbe probe) {
}
