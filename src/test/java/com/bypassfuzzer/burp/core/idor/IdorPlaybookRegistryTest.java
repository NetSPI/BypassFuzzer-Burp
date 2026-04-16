package com.bypassfuzzer.burp.core.idor;

import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IdorPlaybookRegistryTest {

    @Test
    void registryExposesStableSeedPlaybookIds() {
        List<String> ids = new IdorPlaybookRegistry().all().stream()
            .map(IdorPlaybook::id)
            .toList();

        assertEquals(List.of(
            "idor.path.suffix_formats",
            "idor.path.trailing_slash",
            "idor.path.special_identifier_values",
            "idor.path.dot_segments",
            "idor.query.conflicting_identifiers",
            "idor.query.parameter_pollution",
            "idor.query.comma_separated_identifiers",
            "idor.query.json_wrap",
            "idor.query.identifier_aliases",
            "idor.query.numeric_pivots",
            "idor.body.content_type_tampering",
            "idor.body.json_wrap",
            "idor.body.deserialization_hints",
            "idor.body.json_batch_identifiers",
            "idor.body.json_parameter_pollution",
            "idor.body.json_edge_cases",
            "idor.body.wildcard_identifiers",
            "idor.body.unexpected_data_types",
            "idor.hybrid.trailing_control_characters",
            "idor.hybrid.empty_identifier_values",
            "idor.hybrid.resource_shortcuts",
            "idor.hybrid.case_variants",
            "idor.hybrid.canonical_identifier_formats",
            "idor.hybrid.uuid_neighbor_edits",
            "idor.hybrid.truncated_identifier_variants",
            "idor.hybrid.uuid_version_variants",
            "idor.hybrid.accept_negotiation",
            "idor.hybrid.cross_source_conflicts",
            "idor.hybrid.query_body_cross_source",
            "idor.hybrid.identifier_encoding",
            "idor.hybrid.method_override"
        ), ids);
    }
}
