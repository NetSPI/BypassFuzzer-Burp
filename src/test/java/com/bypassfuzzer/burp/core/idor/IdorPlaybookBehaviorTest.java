package com.bypassfuzzer.burp.core.idor;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.idor.playbooks.AcceptNegotiationPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.CanonicalIdentifierFormatsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.CaseVariantsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.CommaSeparatedIdentifiersPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.ConflictingQueryIdentifiersPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.ContentTypeTamperingPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.CrossSourceConflictsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.DeserializationHintsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.DotSegmentTraversalPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.EmptyIdentifierValuesPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorRequestVariant;
import com.bypassfuzzer.burp.core.idor.playbooks.IdentifierAliasesPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.JsonBatchIdentifiersPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.JsonWrapPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.NumericPivotsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.ParameterPollutionPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.JsonParameterPollutionPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.QueryJsonWrapPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.ResourceShortcutPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.SpecialIdentifierValuesPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.SuffixFormatPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.TrailingControlCharactersPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.TruncatedIdentifierVariantsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.UnexpectedDataTypesPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.UuidNeighborEditsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.UuidVersionVariantsPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.WildcardIdentifiersPlaybook;
import com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdorPlaybookBehaviorTest {

    private final IdorRequestContextAnalyzer contextAnalyzer = new IdorRequestContextAnalyzer(
        new IdorRequestMutator((service, rawRequest) -> HttpRequestTestFactory.fromRawRequest(rawRequest))
    );

    @Test
    void dotSegmentPlaybookStartsFromAuthorizedIdentifier() {
        DotSegmentTraversalPlaybook playbook = new DotSegmentTraversalPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(context("/users/1", null, "GET", null, "", "1", "2"));

        assertTrue(variants.stream().anyMatch(variant -> variant.request().path().contains("/users/1/../2")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().path().contains("/users/1/%2E%2E/2")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().path().contains("/users/1%2F..%2F2")));
    }

    @Test
    void dotSegmentPlaybookAlsoMutatesDiscoveredBodyIdentifiers() {
        DotSegmentTraversalPlaybook playbook = new DotSegmentTraversalPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"1\"}", "1", "2")
        );

        assertTrue(variants.stream().anyMatch(variant ->
            "application/json".equals(variant.request().headerValue("Content-Type"))
                && variant.request().bodyToString().contains("\"id\":\"1/../2\"")));
        assertTrue(variants.stream().anyMatch(variant ->
            variant.request().bodyToString().contains("\"id\":\"1/%2E%2E/2\"")));
        assertTrue(variants.stream().anyMatch(variant ->
            variant.request().bodyToString().contains("\"id\":\"1%2F..%2F2\"")));
    }

    @Test
    void parameterPollutionPlaybookPreservesDuplicateOrder() {
        ParameterPollutionPlaybook playbook = new ParameterPollutionPlaybook();

        List<String> paths = playbook.buildVariants(context("/users/1", "id=1", "GET", null, "", "1", "2"))
            .stream().map(variant -> variant.request().path()).toList();

        // 2-param (single-append) + 3-param (double-append, mixed only) variants.
        assertTrue(paths.contains("/users/2?id=2&id=1"), paths.toString());
        assertTrue(paths.contains("/users/2?id=2&id=1&id=2"), paths.toString());
        assertTrue(paths.contains("/users/2?id=2&id=2&id=1"), paths.toString());
        assertEquals(3, paths.size(), paths.toString());
    }

    @Test
    void parameterPollutionPlaybookUsesDiscoveredBodyNameWhenNoQueryExists() {
        ParameterPollutionPlaybook playbook = new ParameterPollutionPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"1\"}", "1", "2")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/users/opaque?user_id=1&user_id=2"), paths.toString());
        assertTrue(paths.contains("/users/opaque?user_id=2&user_id=1"), paths.toString());
    }

    @Test
    void commaSeparatedIdentifiersPlaybookBuildsQueryLists() {
        CommaSeparatedIdentifiersPlaybook playbook = new CommaSeparatedIdentifiersPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/users/opaque", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/users/opaque?id=def456%2Cabc123"), paths.toString());
        assertTrue(paths.contains("/users/opaque?id=abc123%2Cdef456"), paths.toString());
    }

    @Test
    void queryJsonWrapPlaybookWrapsQueryValuesAsJsonObjects() {
        QueryJsonWrapPlaybook playbook = new QueryJsonWrapPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/users/opaque", "user_id=abc123", "GET", null, "", "abc123", "9")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/users/opaque?user_id=%7B%22id%22%3A9%7D"), paths.toString());
        assertTrue(paths.contains("/users/opaque?user_id=%7B%22user_id%22%3A9%7D"), paths.toString());
    }

    @Test
    void queryJsonWrapPlaybookAvoidsDuplicateIdWrappers() {
        QueryJsonWrapPlaybook playbook = new QueryJsonWrapPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/users/opaque", null, "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertEquals(5, paths.size());
        assertEquals(1, paths.stream().filter(path -> path.equals("/users/opaque?id=%7B%22id%22%3A%22def456%22%7D")).count());
    }

    @Test
    void crossSourceConflictsPlaybookBuildsPathAndQueryConflictMatrix() {
        CrossSourceConflictsPlaybook playbook = new CrossSourceConflictsPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/abc123?id=abc123"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=abc123"), paths.toString());
        assertTrue(paths.contains("/something/accounts/abc123?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=def456"), paths.toString());
    }

    @Test
    void specialIdentifierValuesPlaybookAlsoMutatesDiscoveredBodyIdentifiers() {
        SpecialIdentifierValuesPlaybook playbook = new SpecialIdentifierValuesPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"1\"}", "1", "2")
        );

        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"0\"")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"1\"")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"-1\"")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"%C3%87\"")));
    }

    @Test
    void suffixFormatsPlaybookAlsoMutatesDiscoveredBodyIdentifiers() {
        SuffixFormatPlaybook playbook = new SuffixFormatPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"1\"}", "1", "2")
        );

        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"2.json\"")));
        assertTrue(variants.stream().anyMatch(variant -> variant.request().bodyToString().contains("\"id\":\"2.html\"")));
    }

    @Test
    void suffixFormatsPlaybookAvoidsDuplicatePathVariants() {
        SuffixFormatPlaybook playbook = new SuffixFormatPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/ecm-service/resellers/EWZ/children/RA1/", null, "GET", null, "", "RA1", "BAC")
        ).stream().map(variant -> variant.request().path()).toList();

        assertEquals(3, paths.size());
        assertEquals(1, paths.stream().filter(path -> path.equals("/ecm-service/resellers/EWZ/children/BAC.json/")).count());
        assertTrue(paths.contains("/ecm-service/resellers/EWZ/children/BAC.html/"), paths.toString());
        assertTrue(paths.contains("/ecm-service/resellers/EWZ/children/BAC.json.json/"), paths.toString());
    }

    @Test
    void identifierAliasesPlaybookCoversCommonAlternativeNames() {
        IdentifierAliasesPlaybook playbook = new IdentifierAliasesPlaybook();

        Set<String> paths = playbook.buildVariants(context("/users/opaque", "resourceId=1", "GET", null, "", "1", "2"))
            .stream().map(variant -> variant.request().path()).collect(java.util.stream.Collectors.toSet());

        // resourceId=2 is skipped (identical to baseline). Only alias names emitted.
        assertFalse(paths.contains("/users/opaque?resourceId=2"), paths.toString());
        assertTrue(paths.contains("/users/opaque?resourceId=2&id=2"), paths.toString());
        assertTrue(paths.contains("/users/opaque?resourceId=2&userId=2"), paths.toString());
        assertTrue(paths.contains("/users/opaque?resourceId=2&accountId=2"), paths.toString());
    }

    @Test
    void numericPivotsPlaybookIncludesCommonSentinelValues() {
        NumericPivotsPlaybook playbook = new NumericPivotsPlaybook();

        Set<String> labels = playbook.buildVariants(context("/users/opaque", "id=1", "GET", null, "", "1", "2"))
            .stream().map(IdorRequestVariant::label).collect(java.util.stream.Collectors.toSet());

        assertTrue(labels.contains("id=0 -> /users/opaque"));
        assertTrue(labels.contains("id=1 -> /users/opaque"));
        assertTrue(labels.contains("id=2 -> /users/opaque"));
        assertTrue(labels.contains("id=3 -> /users/opaque"));
        assertTrue(labels.contains("id=-1 -> /users/opaque"));
    }

    @Test
    void numericPivotsPlaybookUsesDiscoveredBodyNameWhenNoQueryExists() {
        NumericPivotsPlaybook playbook = new NumericPivotsPlaybook();

        List<String> labels = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"1\"}", "1", "2")
        ).stream().map(IdorRequestVariant::label).toList();

        assertTrue(labels.contains("user_id=0 -> /users/opaque"), labels.toString());
        assertTrue(labels.contains("user_id=-1 -> /users/opaque"), labels.toString());
    }

    @Test
    void conflictingQueryIdentifiersPlaybookUsesDiscoveredBodyNameWhenNoQueryExists() {
        ConflictingQueryIdentifiersPlaybook playbook = new ConflictingQueryIdentifiersPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"1\"}", "1", "2")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/users/opaque?user_id=1"), paths.toString());
    }

    @Test
    void contentTypeTamperingPlaybookRendersBodyFormats() {
        ContentTypeTamperingPlaybook playbook = new ContentTypeTamperingPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"resourceId\":\"1\"}", "1", "2")
        );

        assertEquals(9, variants.size());
        assertTrue(variants.stream().anyMatch(variant ->
            "POST".equals(variant.request().method())
                && "application/x-www-form-urlencoded".equals(variant.request().headerValue("Content-Type"))
                && "resourceId=2".equals(variant.request().bodyToString())));
        assertTrue(variants.stream().anyMatch(variant ->
            "application/json".equals(variant.request().headerValue("Content-Type"))
                && variant.request().bodyToString().contains("\"resourceId\":\"2\"")));
        assertTrue(variants.stream().anyMatch(variant ->
            "application/xml".equals(variant.request().headerValue("Content-Type"))
                && variant.request().bodyToString().contains("<resourceId>2</resourceId>")));
        assertTrue(variants.stream().anyMatch(variant ->
            variant.request().headerValue("Content-Type").startsWith("multipart/form-data; boundary=")
                && variant.request().bodyToString().contains("name=\"resourceId\"")));
        assertTrue(variants.stream().anyMatch(variant ->
            "application/x-www-form-urlencoded".equals(variant.request().headerValue("Content-Type"))
                && "{\"resourceId\":\"2\"}".equals(variant.request().bodyToString())));
        assertTrue(variants.stream().anyMatch(variant ->
            variant.request().headerValue("Content-Type").startsWith("multipart/form-data; boundary=")
                && variant.request().bodyToString().contains("Content-Type: application/x-www-form-urlencoded")
                && variant.request().bodyToString().contains("resourceId=2")));
    }

    @Test
    void contentTypeTamperingPlaybookSkipsWhenIdentifierIsOnlyInPath() {
        ContentTypeTamperingPlaybook playbook = new ContentTypeTamperingPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/1", null, "GET", null, "", "1", "2")
        );

        assertTrue(variants.isEmpty());
    }

    @Test
    void acceptNegotiationPlaybookSetsRepresentativeAcceptHeaders() {
        AcceptNegotiationPlaybook playbook = new AcceptNegotiationPlaybook();

        List<HttpRequest> requests = playbook.buildVariants(
            context("/users/opaque", null, "GET", null, "", "1", "2")
        ).stream().map(IdorRequestVariant::request).toList();

        assertTrue(requests.stream().anyMatch(request -> "application/json".equals(request.headerValue("Accept"))));
        assertTrue(requests.stream().anyMatch(request -> "application/xml".equals(request.headerValue("Accept"))));
        assertTrue(requests.stream().anyMatch(request -> "text/html".equals(request.headerValue("Accept"))));
        assertTrue(requests.stream().anyMatch(request -> "*/*".equals(request.headerValue("Accept"))));
    }

    @Test
    void jsonWrapPlaybookWrapsExistingJsonIdentifierFieldInPlace() {
        JsonWrapPlaybook playbook = new JsonWrapPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":111,\"meta\":{\"id\":222}}", "111", "999")
        );

        assertEquals(1, variants.size());
        assertTrue(variants.stream().anyMatch(variant ->
            "application/json".equals(variant.request().headerValue("Content-Type"))
                && "{\"id\":{\"id\":999},\"meta\":{\"id\":222}}".equals(variant.request().bodyToString())));
    }

    @Test
    void jsonWrapPlaybookSkipsWhenIdentifierIsOnlyInPath() {
        JsonWrapPlaybook playbook = new JsonWrapPlaybook();

        List<IdorRequestVariant> variants = playbook.buildVariants(
            context("/users/1", null, "GET", null, "", "1", "2")
        );

        assertTrue(variants.isEmpty());
    }

    @Test
    void deserializationHintsPlaybookBuildsTypedAndPrototypeLikeJsonObjects() {
        DeserializationHintsPlaybook playbook = new DeserializationHintsPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"user_id\":{\"@type\":\"java.lang.String\",\"user_id\":\"def456\"}}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":{\"@class\":\"java.lang.String\",\"user_id\":\"def456\"}}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":{\"$type\":\"java.lang.String\",\"user_id\":\"def456\"}}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":{\"_class\":\"java.lang.String\",\"user_id\":\"def456\"}}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":{\"__proto__\":{\"user_id\":\"def456\"}}}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":{\"constructor\":{\"prototype\":{\"user_id\":\"def456\"}}}}"), bodies.toString());
    }

    @Test
    void jsonBatchIdentifiersPlaybookWrapsDiscoveredJsonFieldsAsArrays() {
        JsonBatchIdentifiersPlaybook playbook = new JsonBatchIdentifiersPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"users\":\"111\"}", "111", "222")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"users\":[222]}"), bodies.toString());
        assertTrue(bodies.contains("{\"users\":[111,222]}"), bodies.toString());
        assertTrue(bodies.contains("{\"users\":[222,111]}"), bodies.toString());
    }

    @Test
    void jsonParameterPollutionPlaybookDuplicatesJsonKeysInBothOrders() {
        JsonParameterPollutionPlaybook playbook = new JsonParameterPollutionPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"user_id\":\"abc123\",\"user_id\":\"def456\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":\"def456\",\"user_id\":\"abc123\"}"), bodies.toString());
    }

    @Test
    void wildcardIdentifiersPlaybookMutatesDiscoveredJsonBodyFields() {
        WildcardIdentifiersPlaybook playbook = new WildcardIdentifiersPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"user_id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"user_id\":\"*\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":\"%\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":\"_\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"user_id\":\".\"}"), bodies.toString());
    }

    @Test
    void unexpectedDataTypesPlaybookMutatesJsonIdentifierTypes() {
        UnexpectedDataTypesPlaybook playbook = new UnexpectedDataTypesPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"username\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"username\":true}"), bodies.toString());
        assertTrue(bodies.contains("{\"username\":null}"), bodies.toString());
        assertTrue(bodies.contains("{\"username\":1}"), bodies.toString());
        assertTrue(bodies.contains("{\"username\":[true]}"), bodies.toString());
        assertTrue(bodies.contains("{\"username\":[\"def456\",true]}"), bodies.toString());
        assertTrue(bodies.contains("{\"username\":{\"$ne\":\"def456\"}}"), bodies.toString());
    }

    @Test
    void trailingControlCharactersPlaybookMutatesPathAndQueryIdentifiers() {
        TrailingControlCharactersPlaybook playbook = new TrailingControlCharactersPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/def456%20?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=def456%20"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456%09?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/%20def456?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=%20def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456%00?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456%0d%0aabc123?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=def456;abc123"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=def456#abc123"), paths.toString());
    }

    @Test
    void trailingControlCharactersPlaybookMutatesDiscoveredBodyIdentifiers() {
        TrailingControlCharactersPlaybook playbook = new TrailingControlCharactersPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"def456%20\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456%09\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456%1f\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"%20def456\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"%20def456%20\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456%00\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456%0d%0aabc123\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456;abc123\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"def456|abc123\"}"), bodies.toString());
    }

    @Test
    void caseVariantsPlaybookMutatesPathAndQueryIdentifiers() {
        CaseVariantsPlaybook playbook = new CaseVariantsPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/DEF456?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=DeF456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=dEf456"), paths.toString());
    }

    @Test
    void caseVariantsPlaybookMutatesDiscoveredBodyIdentifiers() {
        CaseVariantsPlaybook playbook = new CaseVariantsPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"DEF456\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"DeF456\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"dEf456\"}"), bodies.toString());
    }

    @Test
    void canonicalIdentifierFormatsPlaybookMutatesUuidPathAndQueryIdentifiers() {
        CanonicalIdentifierFormatsPlaybook playbook = new CanonicalIdentifierFormatsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/" + authorized, "id=" + authorized, "GET", null, "", authorized, target)
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/550e8400e29b41d4a716446655440000?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/{" + target + "}?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/" + target + "?id=550E8400-E29B-41D4-A716-446655440000"), paths.toString());
    }

    @Test
    void canonicalIdentifierFormatsPlaybookMutatesUuidBodyIdentifiers() {
        CanonicalIdentifierFormatsPlaybook playbook = new CanonicalIdentifierFormatsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"" + authorized + "\"}", authorized, target)
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"550e8400e29b41d4a716446655440000\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"{550e8400-e29b-41d4-a716-446655440000}\"}"), bodies.toString());
    }

    @Test
    void uuidNeighborEditsPlaybookMutatesUuidPathAndQueryIdentifiers() {
        UuidNeighborEditsPlaybook playbook = new UuidNeighborEditsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/" + authorized, "id=" + authorized, "GET", null, "", authorized, target)
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/550e8400-e29b-41d4-a716-446655440001?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/" + target + "?id=550e8400-e29b-41d4-a716-446655440001"), paths.toString());
        assertTrue(paths.contains("/something/accounts/550e8400-e29b-41d4-a716-44665544ffff?id=" + target), paths.toString());
    }

    @Test
    void uuidNeighborEditsPlaybookMutatesUuidBodyIdentifiers() {
        UuidNeighborEditsPlaybook playbook = new UuidNeighborEditsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"" + authorized + "\"}", authorized, target)
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"550e8400-e29b-41d4-a716-446655440001\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"550e8400-e29b-41d4-a716-44665544ffff\"}"), bodies.toString());
    }

    @Test
    void truncatedIdentifierVariantsPlaybookMutatesUuidPathAndQueryIdentifiers() {
        TruncatedIdentifierVariantsPlaybook playbook = new TruncatedIdentifierVariantsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/" + authorized, "id=" + authorized, "GET", null, "", authorized, target)
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/550e8400?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/" + target + "?id=55440000"), paths.toString());
        assertTrue(paths.contains("/something/accounts/00000000-0000-0000-0000-000000000000?id=" + target), paths.toString());
    }

    @Test
    void truncatedIdentifierVariantsPlaybookMutatesUuidBodyIdentifiers() {
        TruncatedIdentifierVariantsPlaybook playbook = new TruncatedIdentifierVariantsPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"" + authorized + "\"}", authorized, target)
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"550e8400\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"00000000-0000-0000-0000-000000000000\"}"), bodies.toString());
    }

    @Test
    void uuidVersionVariantsPlaybookMutatesUuidPathAndQueryIdentifiers() {
        UuidVersionVariantsPlaybook playbook = new UuidVersionVariantsPlaybook();
        String authorized = "550e8400-e29b-11d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/" + authorized, "id=" + authorized, "GET", null, "", authorized, target)
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/550e8400-e29b-11d4-a716-446655440000?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/" + target + "?id=550e8400-e29b-51d4-a716-446655440000"), paths.toString());
    }

    @Test
    void uuidVersionVariantsPlaybookMutatesUuidBodyIdentifiers() {
        UuidVersionVariantsPlaybook playbook = new UuidVersionVariantsPlaybook();
        String authorized = "550e8400-e29b-11d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"" + authorized + "\"}", authorized, target)
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"550e8400-e29b-11d4-a716-446655440000\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"550e8400-e29b-51d4-a716-446655440000\"}"), bodies.toString());
    }

    @Test
    void identifierEncodingPlaybookMutatesPathAndQueryIdentifiers() {
        com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook playbook =
            new com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/%64%65%66%34%35%36?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=%64%65%66%34%35%36"), paths.toString());
        assertTrue(paths.contains("/something/accounts/ZGVmNDU2?id=def456"), paths.toString());
    }

    @Test
    void identifierEncodingPlaybookEncodesUuidDelimitersInPathAndQuery() {
        com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook playbook =
            new com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/" + authorized, "id=" + authorized, "GET", null, "", authorized, target)
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/550e8400%2De29b%2D41d4%2Da716%2D446655440000?id=" + target), paths.toString());
        assertTrue(paths.contains("/something/accounts/" + target + "?id=550e8400%2De29b%2D41d4%2Da716%2D446655440000"), paths.toString());
    }

    @Test
    void identifierEncodingPlaybookMutatesDiscoveredBodyIdentifiers() {
        com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook playbook =
            new com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"%64%65%66%34%35%36\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"ZGVmNDU2\"}"), bodies.toString());
    }

    @Test
    void identifierEncodingPlaybookAddsJsonUnicodeEscapeVariantsForJsonBodies() {
        com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook playbook =
            new com.bypassfuzzer.burp.core.idor.playbooks.IdentifierEncodingPlaybook();
        String authorized = "550e8400-e29b-41d4-a716-446655440001";
        String target = "550e8400-e29b-41d4-a716-446655440000";

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"" + authorized + "\"}", authorized, target)
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(
            bodies.contains("{\"id\":\"550e8400\\u002de29b\\u002d41d4\\u002da716\\u002d446655440000\"}"),
            bodies.toString()
        );
    }

    @Test
    void emptyIdentifierValuesPlaybookMutatesPathAndQueryIdentifiers() {
        EmptyIdentifierValuesPlaybook playbook = new EmptyIdentifierValuesPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id="), paths.toString());
        assertTrue(paths.contains("/something/accounts/null?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=undefined"), paths.toString());
        assertTrue(paths.contains("/something/accounts/%20?id=def456"), paths.toString());
    }

    @Test
    void emptyIdentifierValuesPlaybookMutatesDiscoveredBodyIdentifiers() {
        EmptyIdentifierValuesPlaybook playbook = new EmptyIdentifierValuesPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\" \"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":null}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"undefined\"}"), bodies.toString());
    }

    @Test
    void resourceShortcutPlaybookMutatesPathAndQueryIdentifiers() {
        ResourceShortcutPlaybook playbook = new ResourceShortcutPlaybook();

        List<String> paths = playbook.buildVariants(
            context("/something/accounts/abc123", "id=abc123", "GET", null, "", "abc123", "def456")
        ).stream().map(variant -> variant.request().path()).toList();

        assertTrue(paths.contains("/something/accounts/me?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/all?id=def456"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=/me"), paths.toString());
        assertTrue(paths.contains("/something/accounts/def456?id=/all"), paths.toString());
    }

    @Test
    void resourceShortcutPlaybookMutatesDiscoveredBodyIdentifiers() {
        ResourceShortcutPlaybook playbook = new ResourceShortcutPlaybook();

        List<String> bodies = playbook.buildVariants(
            context("/users/opaque", null, "POST", "application/json", "{\"id\":\"abc123\"}", "abc123", "def456")
        ).stream().map(variant -> variant.request().bodyToString()).toList();

        assertTrue(bodies.contains("{\"id\":\"me\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"all\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"/me\"}"), bodies.toString());
        assertTrue(bodies.contains("{\"id\":\"/all\"}"), bodies.toString());
    }

    private IdorRequestContext context(String path, String query, String method, String contentType, String body, String authorized, String target) {
        return contextAnalyzer.analyze(
            HttpRequestTestFactory.request(path, query, method, contentType, body),
            new IdorOptions(authorized, target, new IdorRunOptions(0, Set.of()))
        );
    }
}
