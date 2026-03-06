package com.bypassfuzzer.burp.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Resolves a canonical target URL for Montoya requests.
 */
public class TargetUrlResolver {

    public String resolve(HttpRequest request) {
        String rawUrl = request.url();
        if (isAbsolute(rawUrl)) {
            return rawUrl;
        }

        HttpService service = request.httpService();
        if (service == null || service.host() == null || service.host().isEmpty()) {
            throw new IllegalArgumentException("Unable to resolve target URL: missing HTTP service");
        }

        String path = rawUrl;
        if (path == null || path.isEmpty()) {
            path = request.path();
        }
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        return scheme(service) + "://" + authority(service) + path;
    }

    private boolean isAbsolute(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }

    private String scheme(HttpService service) {
        return service.secure() ? "https" : "http";
    }

    private String authority(HttpService service) {
        boolean defaultPort = (!service.secure() && service.port() == 80)
            || (service.secure() && service.port() == 443);
        if (defaultPort || service.port() <= 0) {
            return service.host();
        }
        return service.host() + ":" + service.port();
    }
}
