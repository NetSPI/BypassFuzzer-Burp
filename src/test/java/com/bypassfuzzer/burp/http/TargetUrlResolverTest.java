package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TargetUrlResolverTest {

    private final TargetUrlResolver resolver = new TargetUrlResolver();

    @Test
    void returnsAbsoluteUrlUnchanged() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.com/admin");

        assertEquals("https://example.com/admin", resolver.resolve(request));
    }

    @Test
    void resolvesRelativeUrlFromHttpService() {
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);

        when(request.url()).thenReturn("/admin?debug=true");
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(8443);
        when(service.secure()).thenReturn(true);

        assertEquals("https://example.com:8443/admin?debug=true", resolver.resolve(request));
    }

    @Test
    void fallsBackToRequestPathWhenUrlIsMissing() {
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);

        when(request.url()).thenReturn(null);
        when(request.path()).thenReturn("/admin");
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(80);
        when(service.secure()).thenReturn(false);

        assertEquals("http://example.com/admin", resolver.resolve(request));
    }
}
