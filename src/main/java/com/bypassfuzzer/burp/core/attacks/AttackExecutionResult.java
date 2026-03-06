package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.message.responses.HttpResponse;

public record AttackExecutionResult(AttackExecutionOutcome outcome, HttpResponse response) {

    public static AttackExecutionResult executed(HttpResponse response) {
        return new AttackExecutionResult(AttackExecutionOutcome.EXECUTED, response);
    }

    public static AttackExecutionResult stopped() {
        return new AttackExecutionResult(AttackExecutionOutcome.STOPPED, null);
    }

    public static AttackExecutionResult timedOut() {
        return new AttackExecutionResult(AttackExecutionOutcome.TIMED_OUT, null);
    }
}
