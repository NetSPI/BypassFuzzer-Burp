package com.bypassfuzzer.burp.testsupport;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.http.RequestSender;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.mock;

public final class AttackTestSupport {

    private AttackTestSupport() {
    }

    public static MontoyaApi api() {
        return mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
    }

    public static AttackExecutor nullResponseExecutor() {
        return new AttackExecutor(new NullResponseRequestSender());
    }

    public static AttackResult findByPayload(List<AttackResult> results, String payload) {
        return results.stream()
            .filter(result -> payload.equals(result.getPayload()))
            .findFirst()
            .orElse(null);
    }

    public static int countOccurrences(String text, String needle) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(needle, index)) >= 0) {
            count++;
            index += needle.length();
        }
        return count;
    }

    private static final class NullResponseRequestSender implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return null;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return null;
        }
    }
}
