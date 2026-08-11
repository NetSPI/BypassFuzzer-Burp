package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepCandidate;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepEngine;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbe;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbeGenerator;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPreview;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JTable;
import javax.swing.JTextField;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CoverageSweepPanelTest {

    @TempDir
    Path tempDir;

    @Test
    void authenticatedModePassivelyFiltersBySelectedIdentifiersAndSafeMethods() throws Exception {
        HttpRequest get = requestWithHeaders("/account", "", "GET",
            Map.of("Cookie", "theme=dark; JSESSIONID=secret"), "");
        HttpRequest post = requestWithHeaders("/update", "", "POST",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history(get, 200), history(post, 200))));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);

        mode.setSelectedIndex(1);
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertFalse(checkbox(panel, "status401CheckBox").isVisible());
        assertFalse(checkbox(panel, "status403CheckBox").isVisible());
        assertFalse(checkbox(panel, "status3xxCheckBox").isVisible());
        assertFalse(checkbox(panel, "status4xxCheckBox").isVisible());
        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/account", table.getValueAt(0, 3));
        assertFalse(button(panel, "importButton").isEnabled());
        assertFalse(button(panel, "importButton").isVisible());
        assertTrue(button(panel, "loadButton").isVisible());

        checkbox(panel, "includeUnsafeMethodsCheckBox").doClick();
        assertEquals(2, table.getRowCount());

        mode.setSelectedIndex(0);
        assertTrue(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertTrue(checkbox(panel, "status401CheckBox").isVisible());
        assertTrue(checkbox(panel, "status403CheckBox").isVisible());
        assertTrue(checkbox(panel, "status3xxCheckBox").isVisible());
        assertTrue(checkbox(panel, "status4xxCheckBox").isVisible());
    }

    @Test
    void authenticatedHistoryCollectionRunsOffTheSwingEventThread() throws Exception {
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        AtomicBoolean collectedOnEventThread = new AtomicBoolean(true);
        CountDownLatch collectionStarted = new CountDownLatch(1);
        when(engine.collectPreview(any(CoverageSweepOptions.class))).thenAnswer(invocation -> {
            collectedOnEventThread.set(SwingUtilities.isEventDispatchThread());
            collectionStarted.countDown();
            return new CoverageSweepPreview(0, 0, List.of());
        });
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        SwingUtilities.invokeAndWait(() -> {
            fieldUnchecked(panel, "modeComboBox", JComboBox.class).setSelectedIndex(1);
            fieldUnchecked(panel, "loadButton", JButton.class).doClick();
        });

        assertTrue(collectionStarted.await(2, TimeUnit.SECONDS));
        assertFalse(collectedOnEventThread.get());
        for (int i = 0; i < 50
            && field(panel, "candidateLoadWorker", javax.swing.SwingWorker.class) != null; i++) {
            Thread.sleep(20);
            SwingUtilities.invokeAndWait(() -> { });
        }
        panel.cleanup();
    }

    @Test
    void modeSelectorShowsOnlyTheRelevantSourceControls() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);
        JButton load = button(panel, "loadButton");
        JButton importTargets = button(panel, "importButton");

        assertEquals(3, mode.getItemCount());
        assertTrue(load.isVisible());
        assertFalse(importTargets.isVisible());
        assertTrue(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());

        mode.setSelectedIndex(1);

        assertTrue(load.isVisible());
        assertFalse(importTargets.isVisible());
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());

        mode.setSelectedIndex(2);

        assertFalse(load.isVisible());
        assertTrue(importTargets.isVisible());
        assertTrue(importTargets.isEnabled());
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertFalse(checkbox(panel, "status401CheckBox").isVisible());
        assertFalse(checkbox(panel, "status403CheckBox").isVisible());
        assertFalse(checkbox(panel, "status3xxCheckBox").isVisible());
        assertFalse(checkbox(panel, "status4xxCheckBox").isVisible());
    }

    @Test
    void authenticatedModeOffersAnonymousVerification() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);
        JCheckBox verify = checkbox(panel, "verifyUnauthenticatedAccessCheckBox");

        assertTrue(verify.isSelected());
        assertFalse(verify.isVisible());

        mode.setSelectedIndex(1);
        assertTrue(verify.isVisible());
    }

    @Test
    void authenticatedModeExcludesStaticAssetsByDefaultAndCheckboxIncludesThem() throws Exception {
        HttpRequest account = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest script = requestWithHeaders("/static/app.js?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest image = requestWithHeaders("/avatar", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest stylesheet = requestWithHeaders("/static/site.css", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest font = requestWithHeaders("/static/inter.woff", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history(account, 200, "application/json"),
            history(script, 200, "text/plain"),
            history(image, 200, "image/webp"),
            history(stylesheet, 200, "text/plain"),
            history(font, 200, "application/octet-stream")
        )));

        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(1);
        JCheckBox excludeStatic = checkbox(panel, "excludeStaticAssetsCheckBox");
        assertTrue(excludeStatic.isSelected());

        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/account", table.getValueAt(0, 3));

        excludeStatic.doClick();
        button(panel, "loadButton").doClick();

        assertEquals(5, table.getRowCount());
    }

    @Test
    void previewTableUpdatesAfterLoadingProxyHistory() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403))));

        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/blocked", table.getValueAt(0, 3));
        assertTrue(button(panel, "startButton").isEnabled());
    }

    @Test
    void candidateTableColumnsAreSortable() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/z-last", 403),
            history("/a-first", 403)
        )));
        button(panel, "loadButton").doClick();
        JTable table = field(panel, "candidateTable", JTable.class);

        assertTrue(table.getRowSorter() != null);
        table.getRowSorter().toggleSortOrder(3);
        assertEquals("/a-first", table.getValueAt(0, 3));
        assertEquals("/z-last", table.getValueAt(1, 3));

        table.getRowSorter().toggleSortOrder(3);
        assertEquals("/z-last", table.getValueAt(0, 3));
        assertEquals("/a-first", table.getValueAt(1, 3));
    }

    @Test
    void responseStatusCheckboxesControlLoadedHistory() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/redirect", 302),
            history("/blocked", 403),
            history("/missing", 404)
        )));
        JTable table = field(panel, "candidateTable", JTable.class);

        button(panel, "loadButton").doClick();

        assertEquals(1, table.getRowCount());
        assertEquals("/blocked", table.getValueAt(0, 3));

        checkbox(panel, "status3xxCheckBox").setSelected(true);
        checkbox(panel, "status4xxCheckBox").setSelected(true);
        button(panel, "loadButton").doClick();

        assertEquals(3, table.getRowCount());
    }

    @Test
    void importsTargetUrlsFromTextFileIntoPreviewTable() throws Exception {
        Path targets = tempDir.resolve("sweep-targets.txt");
        Files.writeString(targets, String.join(System.lineSeparator(),
            "https://victim.example/admin/users",
            "https://victim.example/admin/info",
            "# ignored comment",
            "not-a-url"
        ));
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(2, 2, List.of(
            candidate("https://victim.example/admin/users", "/admin/users"),
            candidate("https://victim.example/admin/info", "/admin/info")
        ));
        when(engine.collectPreviewFromUrls(anyList(), any(CoverageSweepOptions.class))).thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        JTable table = field(panel, "candidateTable", JTable.class);

        assertTrue(panel.importTargetsFromFile(targets));

        assertEquals(2, table.getRowCount());
        assertTrue(button(panel, "startButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
        assertTrue(button(panel, "previewProbesButton").isEnabled());
        assertEquals("GET", table.getValueAt(0, 1));
        assertEquals("Imported", table.getValueAt(0, 4));
        assertTrue(
            "/admin/info".equals(table.getValueAt(0, 3))
                || "/admin/users".equals(table.getValueAt(0, 3))
        );
        assertEquals(0, field(panel, "resultsWorkspace", SessionResultsWorkspace.class).allResultsCount());
    }

    @Test
    void importsOpenApiYamlThroughImportMode() throws Exception {
        Path spec = tempDir.resolve("openapi.yaml");
        Files.writeString(spec, "openapi: 3.0.0\npaths: {}\n");
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://api.example.test/users", "/users")
        ));
        when(engine.collectPreviewFromOpenApi(anyString(), anyString(), anyString(), any(CoverageSweepOptions.class)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        assertTrue(panel.importTargetsFromFile(spec));

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/users", table.getValueAt(0, 3));
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("OpenAPI operation"));
    }

    @Test
    void importModeCheckboxTogglesStateChangingRequestSelectionWithoutHidingRows() throws Exception {
        Path spec = tempDir.resolve("openapi.yaml");
        Files.writeString(spec, "openapi: 3.0.0\npaths: {}\n");
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(3, 3, List.of(
            candidate("https://api.example.test/users", "/users", "GET"),
            candidate("https://api.example.test/users", "/users", "POST"),
            candidate("https://api.example.test/users/1", "/users/1", "DELETE")
        ));
        when(engine.collectPreviewFromOpenApi(anyString(), anyString(), anyString(), any(CoverageSweepOptions.class)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);
        JCheckBox includeStateChanging = checkbox(panel, "includeUnsafeMethodsCheckBox");

        assertTrue(includeStateChanging.isEnabled());
        assertFalse(includeStateChanging.isSelected());
        assertTrue(panel.importTargetsFromFile(spec));

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", false);
        assertMethodSelected(table, "DELETE", false);

        includeStateChanging.doClick();
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", true);
        assertMethodSelected(table, "DELETE", true);

        includeStateChanging.doClick();
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", false);
        assertMethodSelected(table, "DELETE", false);
    }

    @Test
    void importTargetsButtonDisablesWhileSweepRuns() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403)), 250));
        button(panel, "loadButton").doClick();

        button(panel, "startButton").doClick();

        assertFalse(button(panel, "importButton").isEnabled());

        button(panel, "stopButton").doClick();
    }

    @Test
    void previewProbesButtonEnablesAfterLoadingCandidates() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403))));

        assertFalse(button(panel, "previewProbesButton").isEnabled());
        assertFalse(button(panel, "viewCandidateButton").isEnabled());

        button(panel, "loadButton").doClick();

        assertTrue(button(panel, "previewProbesButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
    }

    @Test
    void probePreviewRendersExactGeneratedRequests() {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        HttpRequest request = request("/admin/users", "", "GET", null, "");
        HttpResponse response = response(403, "text/plain", "blocked");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(
            request,
            response,
            "key",
            request.url(),
            request.method(),
            "example.com",
            request.path(),
            403,
            response.body().length(),
            "text/plain",
            ZonedDateTime.now()
        );
        List<CoverageSweepProbe> probes = new CoverageSweepProbeGenerator().buildProbes(candidate.request(), CoverageSweepOptions.defaults());

        String preview = panel.renderProbePreview(candidate, probes);

        assertTrue(preview.contains("Probe count: 162"));
        assertTrue(preview.contains("Matrix / Extension - Path suffix ;.json"));
        assertTrue(preview.contains("GET /admin/users;.json HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?format=json HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?_format=json HTTP/1.1"));
        assertTrue(preview.contains("GET //admin/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin///users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/;/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/%3b/users HTTP/1.1"));
        assertTrue(preview.contains("GET /ADMIN/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/USERS HTTP/1.1"));
        assertTrue(preview.contains("GET /AdMiN/uSeRs HTTP/1.1"));
        assertTrue(preview.contains("GET /%61dmin/users HTTP/1.1"));
        assertTrue(preview.contains("Encoding - Double URL encode path character 1"));
        assertTrue(preview.contains("GET /%2561dmin/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?debug=true HTTP/1.1"));
        assertTrue(preview.contains("Content-Type - Content-Type application/json"));
        assertTrue(preview.contains("Content-Type: application/json"));
    }

    @Test
    void startAndStopButtonsReflectRunningState() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/blocked", 403),
            history("/another-blocked", 403)
        ), 250));
        button(panel, "loadButton").doClick();

        button(panel, "startButton").doClick();

        assertFalse(button(panel, "loadButton").isEnabled());
        assertFalse(button(panel, "startButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
        assertFalse(button(panel, "previewProbesButton").isEnabled());
        assertTrue(button(panel, "stopButton").isEnabled());
        assertFalse(field(panel, "concurrencyField", JTextField.class).isEnabled());
        assertFalse(field(panel, "throttleStatusCodesField", JTextField.class).isEnabled());
        JTable candidateTable = field(panel, "candidateTable", JTable.class);
        assertTrue(candidateTable.isEnabled());
        assertFalse(candidateTable.isCellEditable(0, 0));
        candidateTable.setRowSelectionInterval(1, 1);
        assertEquals(1, candidateTable.getSelectedRow());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());

        button(panel, "stopButton").doClick();
    }

    @Test
    void sweepResultsAppearInWorkspace() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403)), 0));
        button(panel, "loadButton").doClick();

        assertFalse(button(panel, "exportButton").isEnabled());

        button(panel, "startButton").doClick();

        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        for (int i = 0; i < 50 && (workspace.allResultsCount() == 0 || !button(panel, "exportButton").isEnabled()); i++) {
            Thread.sleep(20);
        }

        assertTrue(workspace.allResultsCount() > 0);
        assertTrue(button(panel, "exportButton").isEnabled());
    }

    @Test
    void exportsVisibleSweepResultsToTsv() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        HttpRequest request = request("/admin", "", "GET", null, "");
        HttpResponse response = response(200, "application/json", "{\"ok\":true}");
        workspace.addResult(new AttackResult(
            "Coverage Sweep",
            "payload\twith\nunsafe whitespace",
            "GET /admin",
            "Matrix / Extension",
            "403 -> 200",
            request,
            response
        ));

        Path output = tempDir.resolve("sweep-results.tsv");

        assertTrue(panel.exportResultsToTsv(output));

        String tsv = Files.readString(output);
        assertTrue(tsv.startsWith("#\tTarget\tFamily\tSignal\tPayload\tStatus\tLength\tContent-Type"));
        assertTrue(tsv.contains("GET /admin\tMatrix / Extension\t403 -> 200\tpayload with unsafe whitespace\t200"));
        assertFalse(tsv.contains("payload\twith"));
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history) {
        return api(history, 0);
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history, long responseDelayMs) {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        when(api.scope().isInScope(any())).thenReturn(true);
        when(api.proxy().history(any())).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return history.stream().filter(filter::matches).toList();
        });

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpResponse response = response(403, "text/plain", "blocked");
        when(requestResponse.response()).thenReturn(response);
        when(api.http().sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            if (responseDelayMs > 0) {
                Thread.sleep(responseDelayMs);
            }
            return requestResponse;
        });
        return api;
    }

    private ProxyHttpRequestResponse history(String path, int status) {
        HttpRequest request = request(path, "", "GET", null, "");
        return history(request, status);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status) {
        return history(request, status, "text/plain");
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, String contentType) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpResponse response = response(status, contentType, "blocked");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now());
        return item;
    }

    private CoverageSweepCandidate candidate(String displayUrl, String path) {
        return candidate(displayUrl, path, "GET");
    }

    private CoverageSweepCandidate candidate(String displayUrl, String path, String method) {
        HttpRequest request = request(path, "", method, null, "");
        HttpResponse response = response(0, "", "");
        return new CoverageSweepCandidate(
            request,
            null,
            displayUrl,
            displayUrl,
            method,
            "victim.example",
            path,
            0,
            0,
            "",
            ZonedDateTime.now()
        );
    }

    private void assertMethodSelected(JTable table, String method, boolean expected) {
        for (int row = 0; row < table.getRowCount(); row++) {
            if (method.equals(table.getValueAt(row, 1))) {
                assertEquals(expected, table.getValueAt(row, 0));
                return;
            }
        }
        throw new AssertionError("No imported row found for method " + method);
    }

    private HttpResponse response(int status, String contentType, String body) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray bodyBytes = mock(ByteArray.class);
        when(bodyBytes.length()).thenReturn(body == null ? 0 : body.length());
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(bodyBytes);
        when(response.headers()).thenReturn(List.of(header("Content-Type", contentType)));
        return response;
    }

    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }

    private JButton button(CoverageSweepPanel panel, String fieldName) throws Exception {
        return field(panel, fieldName, JButton.class);
    }

    private JCheckBox checkbox(CoverageSweepPanel panel, String fieldName) throws Exception {
        return field(panel, fieldName, JCheckBox.class);
    }

    private <T> T field(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }

    private <T> T fieldUnchecked(Object target, String fieldName, Class<T> type) {
        try {
            return field(target, fieldName, type);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
