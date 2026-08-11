package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.bypassfuzzer.burp.testsupport.AttackTestSupport.api;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderAttackHostPortTest {

    @Test
    void doublePortFamilyUsesHttp1WhileExistingHeaderPayloadsStayAutomatic() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", "example.com:8443");
        HttpRequest request = requestWithHeaders("/forbidden", "", "GET", headers, "");
        ModeTrackingSender sender = new ModeTrackingSender();
        List<AttackResult> results = new ArrayList<>();

        new HeaderAttack("https://example.com/forbidden", null, false).execute(
            api(),
            request,
            "https://example.com/forbidden",
            results::add,
            () -> true,
            null,
            new AttackExecutor(sender)
        );

        assertTrue(sender.automaticSendCount > 0);
        assertFalse(sender.http1Requests.isEmpty());
        assertTrue(sender.http1Requests.stream()
            .map(sent -> sent.headerValue("Host"))
            .anyMatch("example.com:8443:80"::equals));
        assertTrue(sender.http1Requests.stream()
            .allMatch(sent -> sent.httpService().host().equals("example.com") && sent.httpService().port() == 443));
        assertTrue(results.stream()
            .map(AttackResult::getPayload)
            .anyMatch(payload -> payload.contains("double-port numeric matrix")));
    }

    private static final class ModeTrackingSender implements RequestSender {
        private int automaticSendCount;
        private final List<HttpRequest> http1Requests = new ArrayList<>();

        @Override
        public HttpResponse send(HttpRequest request) {
            automaticSendCount++;
            return null;
        }

        @Override
        public HttpResponse send(HttpRequest request, HttpMode httpMode) {
            if (httpMode == HttpMode.HTTP_1) {
                http1Requests.add(request);
            }
            return null;
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return null;
        }
    }
}
