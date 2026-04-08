package com.bypassfuzzer.burp.core.idor.playbooks;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * One concrete request emitted by an IDOR playbook.
 */
public record IdorRequestVariant(
    String label,
    HttpRequest request
) {
}
