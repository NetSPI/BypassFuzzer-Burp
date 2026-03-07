package com.bypassfuzzer.burp.core.filter;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ResultFilterControllerTest {

    @Test
    void appliesManualAndHighlightFilters() {
        ResultFilterController controller = new ResultFilterController();
        controller.filterConfig().setManualFilterEnabled(true);
        controller.filterConfig().setShownStatusCodes(java.util.Set.of(200));
        controller.filterConfig().setContentTypeFilter("json");

        AttackResult jsonResult = result("json", 200, "application/json", "{\"ok\":true}");
        AttackResult htmlResult = result("html", 200, "text/html", "<html></html>");

        controller.highlighter().highlight(jsonResult, controller.highlighter().colorFromName("Red"));
        controller.setHighlightColorFilter("Red");

        assertTrue(controller.shouldShow(jsonResult));
        assertFalse(controller.shouldShow(htmlResult));
    }

    @Test
    void smartFilterSuppressesRepeatingPatternsAfterLimit() {
        ResultFilterController controller = new ResultFilterController();
        controller.filterConfig().setSmartFilterEnabled(true);

        AttackResult last = null;
        for (int i = 0; i < 11; i++) {
            last = result("payload-" + i, 200, "text/html", "<html>same</html>");
            controller.track(last);
        }

        assertFalse(controller.shouldShow(last));
    }

    private AttackResult result(String payload, int statusCode, String contentType, String body) {
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        HttpHeader header = mock(HttpHeader.class);
        ByteArray byteArray = byteArray(body.length());
        when(header.name()).thenReturn("Content-Type");
        when(header.value()).thenReturn(contentType);
        when(response.statusCode()).thenReturn((short) statusCode);
        when(response.body()).thenReturn(byteArray);
        when(response.headers()).thenReturn(List.of(header));
        return new AttackResult("Attack", payload, request, response);
    }

    private ByteArray byteArray(int length) {
        return (ByteArray) Proxy.newProxyInstance(
            ByteArray.class.getClassLoader(),
            new Class<?>[]{ByteArray.class},
            (proxy, invokedMethod, args) -> switch (invokedMethod.getName()) {
                case "length" -> length;
                case "iterator" -> Collections.<Byte>emptyIterator();
                case "toString" -> "";
                default -> null;
            }
        );
    }
}
