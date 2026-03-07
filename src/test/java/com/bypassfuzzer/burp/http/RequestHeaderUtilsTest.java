package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RequestHeaderUtilsTest {

    @Test
    void updatesExistingHeaderInsteadOfAppendingDuplicate() {
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest updated = mock(HttpRequest.class);
        when(request.hasHeader("Host")).thenReturn(true);
        when(request.withUpdatedHeader("Host", "0.0.0.0")).thenReturn(updated);

        HttpRequest result = RequestHeaderUtils.upsertHeader(request, "Host", "0.0.0.0");

        assertSame(updated, result);
        verify(request).withUpdatedHeader("Host", "0.0.0.0");
    }

    @Test
    void addsHeaderWhenNameIsNotAlreadyPresent() {
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest updated = mock(HttpRequest.class);
        when(request.hasHeader("X-Forwarded-For")).thenReturn(false);
        when(request.withAddedHeader("X-Forwarded-For", "127.0.0.1")).thenReturn(updated);

        HttpRequest result = RequestHeaderUtils.upsertHeader(request, "X-Forwarded-For", "127.0.0.1");

        assertSame(updated, result);
        verify(request).withAddedHeader("X-Forwarded-For", "127.0.0.1");
    }

    @Test
    void preservesExistingCookieDuringHeaderAttack() {
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest updated = mock(HttpRequest.class);
        when(request.headerValue("Cookie")).thenReturn("session=abc123");
        when(request.withUpdatedHeader("Cookie", "session=abc123; debug=true")).thenReturn(updated);

        HttpRequest result = RequestHeaderUtils.applyAttackHeader(request, "Cookie", "debug=true");

        assertSame(updated, result);
        verify(request).withUpdatedHeader("Cookie", "session=abc123; debug=true");
    }

    @Test
    void overwritesAuthorizationDuringHeaderAttack() {
        HttpRequest request = mock(HttpRequest.class);
        HttpRequest updated = mock(HttpRequest.class);
        when(request.hasHeader("Authorization")).thenReturn(true);
        when(request.withUpdatedHeader("Authorization", "Basic A")).thenReturn(updated);

        HttpRequest result = RequestHeaderUtils.applyAttackHeader(request, "Authorization", "Basic A");

        assertSame(updated, result);
        verify(request).withUpdatedHeader("Authorization", "Basic A");
    }
}
