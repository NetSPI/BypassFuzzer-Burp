package com.bypassfuzzer.burp.smoke;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.RateLimiter;
import com.bypassfuzzer.burp.core.attacks.AttackExecutor;
import com.bypassfuzzer.burp.core.attacks.AttackRegistry;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.attacks.AttackStrategy;
import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.attacks.RegisteredAttack;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(90)
class AttackPlaybookSmokeTest {

    private static final String HOST = "127.0.0.1";
    private static final AttackRegistry ATTACK_REGISTRY = new AttackRegistry();

    private static Process smokeLab;
    private static String baseUrl;
    private static int port;

    @BeforeAll
    static void startLab() throws Exception {
        port = findFreePort();
        baseUrl = "http://" + HOST + ":" + port;

        smokeLab = new ProcessBuilder("python3", "src/test/smoke_lab/app.py", "--host", HOST, "--port", Integer.toString(port))
            .directory(Path.of(".").toFile())
            .redirectErrorStream(true)
            .start();

        waitForLab(baseUrl);
    }

    @AfterAll
    static void stopLab() {
        if (smokeLab != null) {
            smokeLab.destroy();
            try {
                if (!smokeLab.waitFor(3, TimeUnit.SECONDS)) {
                    smokeLab.destroyForcibly();
                    smokeLab.waitFor(3, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                smokeLab.destroyForcibly();
            }
        }
    }

    @Test
    void headerAttackFindsHeaderBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.HEADER,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "trusted Authorization"
            )
        );
    }

    @Test
    void pathAttackFindsPathNormalizationBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PATH,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void verbAttackFindsMethodConfusionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.VERB,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "method confusion"
            )
        );
    }

    @Test
    void paramAttackFindsTruthyQueryBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PARAM,
                "/api/admin/settings?debug=false",
                """
                    GET /api/admin/settings?debug=false HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "truthy query parameter"
            )
        );
    }

    @Test
    void cookieAttackFindsTruthyCookieBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.COOKIE,
                "/api/admin/settings",
                """
                    GET /api/admin/settings HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user; debug=false\r
                    \r
                    """,
                "truthy cookie parameter"
            )
        );
    }

    @Test
    void trailingDotAttackFindsHostBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.TRAILING_DOT,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "trusted trailing-dot Host"
            )
        );
    }

    @Test
    void trailingSlashAttackFindsPathBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.TRAILING_SLASH,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void extensionAttackFindsExtensionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.EXTENSION,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void contentTypeAttackFindsParserConfusionBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.CONTENT_TYPE,
                "/api/admin/settings?debug=false",
                """
                    GET /api/admin/settings?debug=false HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "content-type parser confusion"
            )
        );
    }

    @Test
    void encodingAttackFindsEncodedBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.ENCODING,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    @Test
    void protocolAttackFindsHttp10Bypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.PROTOCOL,
                "/protocol/admin",
                """
                    GET /protocol/admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "http-1.0"
            )
        );
    }

    @Test
    void caseAttackFindsCaseBypass() {
        assertAttackSucceeds(
            scenario(
                AttackType.CASE,
                "/admin",
                """
                    GET /admin HTTP/1.1\r
                    Host: %s:%d\r
                    Cookie: session=lab-user\r
                    \r
                    """,
                "path normalization bypass"
            )
        );
    }

    private static Scenario scenario(AttackType type, String pathAndQuery, String rawTemplate, String expectedMarker) {
        String rawRequest = rawTemplate.formatted(HOST, port);
        return new Scenario(type, baseUrl + pathAndQuery, rawRequest, expectedMarker);
    }

    private void assertAttackSucceeds(Scenario scenario) {
        MontoyaApi api = montoyaApi();
        RateLimiter rateLimiter = new RateLimiter(api, 0, Set.of(), false);
        AtomicBoolean running = new AtomicBoolean(true);
        List<AttackResult> results = new ArrayList<>();
        AttackStrategy strategy = attackStrategy(scenario.type(), scenario.targetUrl());
        AttackExecutor executor = new AttackExecutor(new RawSocketRequestSender());

        strategy.execute(
            api,
            baseRequest(scenario.rawRequest()),
            scenario.targetUrl(),
            result -> {
                results.add(result);
                HttpResponse response = result.getResponse();
                if (response != null && response.statusCode() == 200) {
                    String marker = response.headerValue("X-Smoke-Bypass");
                    if (marker != null && marker.contains(scenario.expectedMarker())) {
                        running.set(false);
                    }
                }
            },
            running::get,
            rateLimiter,
            executor
        );

        assertFalse(results.isEmpty(), "No requests were executed for " + scenario.type());
        boolean matched = results.stream().anyMatch(result -> {
            HttpResponse response = result.getResponse();
            return response != null
                && response.statusCode() == 200
                && response.headerValue("X-Smoke-Bypass") != null
                && response.headerValue("X-Smoke-Bypass").contains(scenario.expectedMarker());
        });

        String summary = results.stream()
            .limit(8)
            .map(result -> result.getAttackType() + " :: " + result.getPayload() + " -> " + result.getStatusCode())
            .reduce((left, right) -> left + "\n" + right)
            .orElse("<no results>");
        assertTrue(matched, "Expected marker '%s' for %s. First results:%n%s".formatted(
            scenario.expectedMarker(),
            scenario.type(),
            summary
        ));
    }

    private static AttackStrategy attackStrategy(AttackType type, String targetUrl) {
        if (type == AttackType.PROTOCOL) {
            return new com.bypassfuzzer.burp.core.attacks.ProtocolAttack(MontoyaStubs::request);
        }
        FuzzerConfig config = new FuzzerConfig();
        disableAllAttacks(config);
        enable(config, type);
        List<RegisteredAttack> attacks = ATTACK_REGISTRY.buildEnabledAttacks(config, targetUrl);
        assertFalse(attacks.isEmpty(), "No attack strategy built for " + type);
        return attacks.get(0).strategy();
    }

    private static void disableAllAttacks(FuzzerConfig config) {
        config.setEnableHeaderAttack(false);
        config.setEnablePathAttack(false);
        config.setEnableVerbAttack(false);
        config.setEnableParamAttack(false);
        config.setEnableCookieParamAttack(false);
        config.setEnableTrailingDotAttack(false);
        config.setEnableProtocolAttack(false);
        config.setEnableCaseAttack(false);
        config.setEnableTrailingSlashAttack(false);
        config.setEnableExtensionAttack(false);
        config.setEnableContentTypeAttack(false);
        config.setEnableEncodingAttack(false);
    }

    private static void enable(FuzzerConfig config, AttackType type) {
        switch (type) {
            case HEADER -> config.setEnableHeaderAttack(true);
            case PATH -> config.setEnablePathAttack(true);
            case VERB -> config.setEnableVerbAttack(true);
            case PARAM -> config.setEnableParamAttack(true);
            case COOKIE -> {
                config.setEnableCookieParamAttack(true);
                config.setEnableFuzzExistingCookies(true);
            }
            case TRAILING_DOT -> config.setEnableTrailingDotAttack(true);
            case PROTOCOL -> config.setEnableProtocolAttack(true);
            case CASE -> config.setEnableCaseAttack(true);
            case TRAILING_SLASH -> config.setEnableTrailingSlashAttack(true);
            case EXTENSION -> config.setEnableExtensionAttack(true);
            case CONTENT_TYPE -> config.setEnableContentTypeAttack(true);
            case ENCODING -> config.setEnableEncodingAttack(true);
        }
    }

    private static HttpRequest baseRequest(String rawRequest) {
        return MontoyaStubs.request(MontoyaStubs.httpService(HOST, port, false), rawRequest);
    }

    private static MontoyaApi montoyaApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
            Logging.class.getClassLoader(),
            new Class<?>[]{Logging.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "output" -> System.out;
                case "error" -> System.err;
                case "toString" -> "SmokeLogging";
                default -> null;
            }
        );

        return (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "logging" -> logging;
                case "toString" -> "SmokeMontoyaApi";
                default -> null;
            }
        );
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void waitForLab(String url) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            try {
                if (isLabHealthy()) {
                    return;
                }
            } catch (Exception ignored) {
                // lab not ready yet
            }
            Thread.sleep(100);
        }
        String processOutput = readProcessOutput(smokeLab.getInputStream());
        throw new IllegalStateException("Smoke lab did not become ready at " + url + ". Output: " + processOutput);
    }

    private static boolean isLabHealthy() throws IOException {
        try (Socket socket = new Socket(HOST, port)) {
            socket.setSoTimeout(1000);
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(("GET /health HTTP/1.1\r\nHost: " + HOST + ":" + port + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            socket.shutdownOutput();
            String response = new String(socket.getInputStream().readNBytes(256), StandardCharsets.UTF_8);
            return response.startsWith("HTTP/1.0 200") || response.startsWith("HTTP/1.1 200");
        }
    }

    private static String readProcessOutput(InputStream inputStream) throws IOException {
        byte[] bytes = inputStream.readAllBytes();
        return bytes.length == 0 ? "<no output>" : new String(bytes, StandardCharsets.UTF_8);
    }

    private record Scenario(AttackType type, String targetUrl, String rawRequest, String expectedMarker) {
    }

    private static final class RawSocketRequestSender implements RequestSender {
        @Override
        public HttpResponse send(HttpRequest request) {
            return sendInternal(request, 5, TimeUnit.SECONDS);
        }

        @Override
        public HttpResponse send(HttpRequest request, long timeout, TimeUnit timeUnit) {
            return sendInternal(request, timeout, timeUnit);
        }

        private HttpResponse sendInternal(HttpRequest request, long timeout, TimeUnit timeUnit) {
            try (Socket socket = new Socket(request.httpService().host(), request.httpService().port())) {
                socket.setSoTimeout((int) timeUnit.toMillis(timeout));
                socket.getOutputStream().write(request.toByteArray().getBytes());
                socket.getOutputStream().flush();
                socket.shutdownOutput();

                byte[] bytes = socket.getInputStream().readAllBytes();
                if (bytes.length == 0) {
                    return null;
                }
                return MontoyaStubs.response(bytes);
            } catch (IOException e) {
                return syntheticFailureResponse(e);
            }
        }

        private HttpResponse syntheticFailureResponse(IOException exception) {
            String message = exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
            return MontoyaStubs.syntheticResponse(599, "Smoke Failure", message, List.of());
        }
    }
}
