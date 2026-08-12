package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HeaderRequestTestFactory.values;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AttackExecutorConfiguredHeadersTest {

    @Test
    void sendsAndRecordsTheReconciledDuplicateHeaderRequest() {
        HttpRequest original = request(Map.entry("Authorization", "Bearer captured"));
        HttpRequest mutation = original.withUpdatedHeader("Authorization", "Basic bypass");
        ConfiguredHeaderPolicy policy = new ConfiguredHeaderPolicy(List.of(
            new ConfiguredHeader("Authorization", "Bearer stable")));
        RecordingSender sender = new RecordingSender(response());
        List<AttackResult> results = new ArrayList<>();
        AttackExecutor executor = new AttackExecutor(
            sender, request -> policy.reconcileMutation(original, request));

        executor.execute("Header", "Authorization: Basic bypass", mutation,
            results::add, () -> true, null);

        assertEquals(List.of("Bearer stable", "Basic bypass"), values(sender.sent, "Authorization"));
        assertEquals(sender.sent, results.get(0).getRequest());
    }

    private HttpResponse response() {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(response.body()).thenReturn(body);
        when(body.length()).thenReturn(0);
        when(response.headers()).thenReturn(List.of());
        return response;
    }

    private static final class RecordingSender implements RequestSender {
        private final HttpResponse response;
        private HttpRequest sent;

        private RecordingSender(HttpResponse response) {
            this.response = response;
        }

        @Override
        public HttpResponse send(HttpRequest request) {
            sent = request;
            return response;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return send(request);
        }
    }
}
