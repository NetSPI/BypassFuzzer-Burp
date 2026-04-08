package com.bypassfuzzer.burp.core.idor.playbooks;

import com.bypassfuzzer.burp.core.idor.IdorRequestContext;

import java.util.List;

/**
 * A named, reusable family of IDOR/BOLA request mutations.
 */
public interface IdorPlaybook {

    String id();

    String displayName();

    String description();

    List<IdorRequestVariant> buildVariants(IdorRequestContext context);
}
