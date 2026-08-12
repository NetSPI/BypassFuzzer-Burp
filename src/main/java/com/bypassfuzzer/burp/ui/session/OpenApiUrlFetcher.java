package com.bypassfuzzer.burp.ui.session;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@FunctionalInterface
interface OpenApiUrlFetcher {

    int MAX_SOURCE_BYTES = 10 * 1024 * 1024;

    String fetch(URI uri) throws Exception;

    static OpenApiUrlFetcher http() {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

        return uri -> {
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json, application/yaml, text/yaml, */*;q=0.1")
                .GET()
                .build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new IOException("OpenAPI URL returned HTTP " + response.statusCode());
                }
                byte[] source = body.readNBytes(MAX_SOURCE_BYTES + 1);
                if (source.length > MAX_SOURCE_BYTES) {
                    throw new IOException("OpenAPI document exceeds the 10 MB import limit");
                }
                return new String(source, StandardCharsets.UTF_8);
            }
        };
    }
}
