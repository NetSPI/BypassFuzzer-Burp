package com.bypassfuzzer.burp.http;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CookieHeaderUtilsTest {

    @Test
    void parsesCookieHeaderPreservingOrder() {
        Map<String, String> cookies = CookieHeaderUtils.parse("session=abc; debug=true; theme=light");

        assertEquals("abc", cookies.get("session"));
        assertEquals("true", cookies.get("debug"));
        assertEquals("light", cookies.get("theme"));
    }

    @Test
    void replacesCookieValueWithoutDroppingOthers() {
        String updated = CookieHeaderUtils.replaceValue("session=abc; debug=true; theme=light", "debug", "false");

        assertEquals("session=abc; debug=false; theme=light", updated);
    }

    @Test
    void appendsCookieToExistingHeader() {
        assertEquals("session=abc; debug=true", CookieHeaderUtils.appendCookie("session=abc", "debug=true"));
        assertEquals("debug=true", CookieHeaderUtils.appendCookie("", "debug=true"));
    }
}
