package com.bypassfuzzer.burp.core.payloads;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HostPortBypassPayloadGeneratorTest {

    private final HostPortBypassPayloadGenerator generator = new HostPortBypassPayloadGenerator();

    @Test
    void literalHostPortTakesPrecedenceOverTransportPort() {
        HttpRequest request = request("yahoo.com:8443", "yahoo.com", 443, true);

        List<String> values = values(generator.generate(request, "https://yahoo.com/forbidden"));

        assertTrue(values.contains("yahoo.com:8443:80"));
        assertTrue(values.contains("yahoo.com:8443:443"));
        assertTrue(values.contains("yahoo.com:443:80"));
        assertEquals(1, values.stream().filter("yahoo.com:8443:80"::equals).count());
        assertEquals("yahoo.com", request.httpService().host());
        assertEquals(443, request.httpService().port());
    }

    @Test
    void missingHostUsesServiceAuthorityAndIncludesCommonAlternatePorts() {
        HttpRequest request = request(null, "yahoo.com", 443, true);

        List<String> values = values(generator.generate(request, "https://yahoo.com/forbidden"));

        assertTrue(values.contains("yahoo.com:443:80"));
        assertTrue(values.contains("yahoo.com:8000:80"));
        assertTrue(values.contains("yahoo.com:8443:443"));
        assertTrue(values.contains("yahoo.com::80"));
        assertTrue(values.contains("yahoo.com:443:abc"));
    }

    @Test
    void targetUrlIsUsedWhenHostAndServiceAreUnavailable() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.headerValue("Host")).thenReturn(null);
        when(request.httpService()).thenReturn(null);

        List<String> values = values(generator.generate(request, "http://fallback.example:8081/forbidden"));

        assertTrue(values.contains("fallback.example:8081:80"));
        assertTrue(values.contains("fallback.example:8081:443"));
    }

    @Test
    void lightweightFamilyUsesOnlyCurrentHostPortWithTwoTrailingPorts() {
        HttpRequest request = request("yahoo.com:8443", "yahoo.com", 443, true);

        List<String> values = values(generator.generateLightweight(request));

        assertEquals(List.of("yahoo.com:8443:80", "yahoo.com:8443:443"), values);
    }

    @Test
    void lightweightFamilyUsesConnectionPortWhenHostHasNoPort() {
        HttpRequest request = request("vhost.example", "public.example", 8081, false);

        List<String> values = values(generator.generateLightweight(request));

        assertEquals(List.of("vhost.example:8081:80", "vhost.example:8081:443"), values);
    }

    @Test
    void differingLiteralHostControlsEveryStructuredMutation() {
        HttpRequest request = request("internal.example:8443", "public.example", 443, true);

        List<String> values = values(generator.generate(request, "https://public.example/forbidden"));

        assertFalse(values.isEmpty());
        assertTrue(values.stream().allMatch(value -> value.startsWith("internal.example:")));
        assertTrue(values.contains("internal.example:8443:80"));
        assertTrue(values.contains("internal.example:443:80"));
    }

    @Test
    void malformedLiteralHostIsAppendedDirectlyButServiceDrivesStructuredMatrix() {
        HttpRequest request = request("public.example:8443:123", "public.example", 443, true);

        List<String> values = values(generator.generate(request, "https://public.example/forbidden"));

        assertTrue(values.contains("public.example:8443:123:80"));
        assertTrue(values.contains("public.example:443:80"));
        assertFalse(values.contains("[public.example:8443:123]:443:80"));
    }

    @Test
    void ipv6AuthoritiesRemainBracketed() {
        HttpRequest request = request("[2001:db8::1]:8443", "2001:db8::1", 443, true);

        List<String> values = values(generator.generate(request, "https://[2001:db8::1]/forbidden"));

        assertTrue(values.contains("[2001:db8::1]:8443:80"));
        assertTrue(values.contains("[2001:db8::1]:443:443"));
    }

    private List<String> values(List<HostPortBypassPayloadGenerator.HostPortPayload> payloads) {
        return payloads.stream().map(HostPortBypassPayloadGenerator.HostPortPayload::value).toList();
    }

    private HttpRequest request(String hostHeader, String serviceHost, int servicePort, boolean secure) {
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(request.headerValue("Host")).thenReturn(hostHeader);
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn(serviceHost);
        when(service.port()).thenReturn(servicePort);
        when(service.secure()).thenReturn(secure);
        return request;
    }
}
