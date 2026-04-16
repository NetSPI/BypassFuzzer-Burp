package com.bypassfuzzer.burp.core.idor.playbooks;

import java.util.List;

/**
 * Central registry for IDOR/BOLA playbooks.
 *
 * Add new technique families here by creating a new {@link IdorPlaybook}
 * implementation and registering it in {@link #all()}.
 */
public class IdorPlaybookRegistry {

    public List<IdorPlaybook> all() {
        return List.of(
            // PLAYBOOK: idor.path.suffix_formats
            new SuffixFormatPlaybook(),
            // PLAYBOOK: idor.path.trailing_slash
            new TrailingSlashPlaybook(),
            // PLAYBOOK: idor.path.special_identifier_values
            new SpecialIdentifierValuesPlaybook(),
            // PLAYBOOK: idor.path.dot_segments
            new DotSegmentTraversalPlaybook(),
            // PLAYBOOK: idor.query.conflicting_identifiers
            new ConflictingQueryIdentifiersPlaybook(),
            // PLAYBOOK: idor.query.parameter_pollution
            new ParameterPollutionPlaybook(),
            // PLAYBOOK: idor.query.comma_separated_identifiers
            new CommaSeparatedIdentifiersPlaybook(),
            // PLAYBOOK: idor.query.json_wrap
            new QueryJsonWrapPlaybook(),
            // PLAYBOOK: idor.query.identifier_aliases
            new IdentifierAliasesPlaybook(),
            // PLAYBOOK: idor.query.numeric_pivots
            new NumericPivotsPlaybook(),
            // PLAYBOOK: idor.body.content_type_tampering
            new ContentTypeTamperingPlaybook(),
            // PLAYBOOK: idor.body.json_wrap
            new JsonWrapPlaybook(),
            // PLAYBOOK: idor.body.deserialization_hints
            new DeserializationHintsPlaybook(),
            // PLAYBOOK: idor.body.json_batch_identifiers
            new JsonBatchIdentifiersPlaybook(),
            // PLAYBOOK: idor.body.json_parameter_pollution
            new JsonParameterPollutionPlaybook(),
            // PLAYBOOK: idor.body.json_edge_cases
            new JsonEdgeCasesPlaybook(),
            // PLAYBOOK: idor.body.wildcard_identifiers
            new WildcardIdentifiersPlaybook(),
            // PLAYBOOK: idor.body.unexpected_data_types
            new UnexpectedDataTypesPlaybook(),
            // PLAYBOOK: idor.hybrid.trailing_control_characters
            new TrailingControlCharactersPlaybook(),
            // PLAYBOOK: idor.hybrid.empty_identifier_values
            new EmptyIdentifierValuesPlaybook(),
            // PLAYBOOK: idor.hybrid.resource_shortcuts
            new ResourceShortcutPlaybook(),
            // PLAYBOOK: idor.hybrid.case_variants
            new CaseVariantsPlaybook(),
            // PLAYBOOK: idor.hybrid.canonical_identifier_formats
            new CanonicalIdentifierFormatsPlaybook(),
            // PLAYBOOK: idor.hybrid.uuid_neighbor_edits
            new UuidNeighborEditsPlaybook(),
            // PLAYBOOK: idor.hybrid.truncated_identifier_variants
            new TruncatedIdentifierVariantsPlaybook(),
            // PLAYBOOK: idor.hybrid.uuid_version_variants
            new UuidVersionVariantsPlaybook(),
            // PLAYBOOK: idor.hybrid.accept_negotiation
            new AcceptNegotiationPlaybook(),
            // PLAYBOOK: idor.hybrid.cross_source_conflicts
            new CrossSourceConflictsPlaybook(),
            // PLAYBOOK: idor.hybrid.query_body_cross_source
            new QueryBodyCrossSourcePlaybook(),
            // PLAYBOOK: idor.hybrid.identifier_encoding
            new IdentifierEncodingPlaybook(),
            // PLAYBOOK: idor.hybrid.method_override
            new MethodOverridePlaybook()
        );
    }
}
