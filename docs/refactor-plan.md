# BypassFuzzer Refactor Plan

## Objective

Refactor BypassFuzzer into a maintainable Burp Suite Professional extension with:

- clear separation between Burp integration, fuzzing domain logic, and Swing UI
- deterministic session lifecycle management
- consistent attack execution and request mutation patterns
- testable components with minimal Montoya API coupling
- staged migration that keeps the extension working throughout the refactor

## Current-State Assessment

The codebase is functional, but the current structure concentrates too much behavior in a few classes and mixes UI, orchestration, request mutation, and operational concerns.

### Main Structural Problems

- `FuzzingSessionTab` is a god class and owns UI layout, config parsing, lifecycle, filtering, result presentation, and session orchestration.
- Attack implementations duplicate execution patterns such as stop checks, rate limiting, request dispatch, progress logging, and exception handling.
- Request rewriting logic is spread across large attack classes with ad hoc parsing instead of reusable request mutation utilities.
- Session lifecycle is not modeled explicitly; cleanup behavior is implicit and currently unsafe when tabs are closed.
- Montoya API calls are used directly across UI and attack code, which makes the code hard to test and difficult to reason about.

## Target Architecture

### Package Boundaries

- `com.bypassfuzzer.burp.bootstrap`
  - Burp entry point, extension wiring, unload lifecycle
- `com.bypassfuzzer.burp.session`
  - session controller, session registry, session state, progress events
- `com.bypassfuzzer.burp.domain`
  - immutable request context, result model, attack identifiers, run configuration
- `com.bypassfuzzer.burp.attacks`
  - attack contracts, attack registry, concrete attacks, shared mutation helpers
- `com.bypassfuzzer.burp.http`
  - Burp-backed HTTP client, collaborator service, URL normalization, request mutation helpers
- `com.bypassfuzzer.burp.filter`
  - smart/manual filter engine and filter specifications
- `com.bypassfuzzer.burp.ui`
  - view components only; no direct fuzzing orchestration logic
- `com.bypassfuzzer.burp.resources`
  - payload repositories and template expansion

### Core Design Rules

- UI classes render state and dispatch user intent; they do not own fuzzing workflows.
- Session orchestration lives in a dedicated controller with explicit `start`, `stop`, `close`, and `dispose` operations.
- Each attack declares only how it generates request mutations; common execution mechanics are centralized.
- Montoya API access is wrapped behind narrow interfaces so the domain layer can be unit tested.
- Mutable config parsing happens once at the UI boundary, then flows through immutable config objects.

## Proposed Runtime Model

### Session Layer

- Introduce `FuzzingSessionController` as the owner of one fuzzing session.
- Introduce `SessionRegistry` to track open sessions and guarantee cleanup on tab close and extension unload.
- Introduce `SessionState` and `SessionEvent` to model progress, completion, stopping, and failure explicitly.

### Attack Layer

- Replace the current `AttackStrategy` execution contract with a split contract:
  - `AttackDefinition` identifies the attack and declares prerequisites.
  - `AttackGenerator` yields request mutations or executable attack steps.
  - `AttackExecutor` runs shared mechanics: stop checks, rate limiting, logging, request dispatch, and result creation.
- Add shared helpers for:
  - path extraction and URL normalization
  - query/body/cookie parsing and rewriting
  - content-type transformation
  - payload expansion and deduplication

### HTTP Layer

- Introduce `RequestSender` as the only service that talks to `api.http()`.
- Introduce `CollaboratorService` so collaborator availability and payload generation are not spread across UI and attacks.
- Introduce `TargetUrlResolver` to produce canonical target metadata from Burp requests without guessing protocol from scope.

### UI Layer

- Split `FuzzingSessionTab` into:
  - `FuzzingSessionPanel` for layout and widgets
  - `FuzzingSessionPresenter` or controller adapter for translating user actions into session commands
  - `FilterPanel`, `AttackSelectionPanel`, and `ResultDetailPanel` subcomponents
- Keep the table model focused on presentation; move filtering state and result bookkeeping out of the Swing model.

## Refactor Phases

### Phase 1 Status

Implemented:

- added `SessionRegistry` and `FuzzingSessionController` so sessions have explicit ownership and disposal
- wired tab close and extension unload through registry-backed session cleanup
- moved run completion signaling out of Swing polling and into the session controller lifecycle
- added `TargetUrlResolver` so relative requests resolve from `HttpService` instead of Burp scope guesses
- enforced the Collaborator toggle in `HeaderAttack`
- centralized pre-send stop/rate-limit checks with `AttackExecutionSupport`
- added initial regression tests for target URL resolution and interrupt-aware rate limiting

### Phase 1: Stabilize Lifecycle and Contracts

- Add `SessionRegistry` and ensure tab close always stops and disposes the matching session.
- Introduce a session-scoped controller so UI no longer talks directly to `FuzzerEngine`.
- Stop relying on ad hoc worker and monitor threads from the UI.
- Fix stop semantics so interruption cannot send extra requests after the user clicks stop.

### Phase 2: Extract Shared Execution Services

- Create `RequestSender`, `AttackExecutor`, `TargetUrlResolver`, and `PayloadRepository`.
- Migrate `FuzzerEngine` into a thin coordinator over an `AttackRegistry`.
- Centralize progress logging, rate limiting, exception mapping, and result creation.

Status:

- `TargetUrlResolver` is implemented and in use.
- `AttackRegistry` is implemented and now owns attack ordering/construction.
- attack enablement is typed via `AttackType` instead of raw string ids.
- `RequestSender` and `AttackExecutor` are implemented and the standard attacks now route through them.
- timeout-aware protocol dispatch also routes through the shared sender/executor path.

### Phase 3: Decompose UI

- Break `FuzzingSessionTab` into focused Swing components.
- Move config parsing and validation into a dedicated mapper.
- Replace direct UI mutation from background workflows with explicit session events.

Status:

- session startup options now flow through `SessionRunOptions` instead of inline checkbox-to-config mapping
- preflight warning analysis now lives in `SessionPreflightAnalyzer`
- session state changes already flow through controller events
- attack selection and run options UI now live in dedicated Swing subcomponents
- filter panel and result area decomposition are still pending if further UI cleanup is needed

### Phase 4: Normalize Attack Implementations

- Refactor each attack to use shared request mutation utilities.
- Remove duplicated parsing logic from parameter, cookie, verb, content-type, and encoding attacks.
- Make attack enablement data-driven with an `AttackType` enum and registry metadata.

### Phase 5: Add Tests and Regression Harness

- Add unit tests for:
  - URL resolution
  - request mutation helpers
  - filter decisions
  - rate limiting and stop behavior
  - payload expansion
- Add attack-focused tests with mocked request sender behavior.
- Add smoke tests for session lifecycle and attack registry composition.

## Immediate Refactor Backlog

### Must Fix Before Feature Work

- session close must dispose the corresponding engine and unregister the session
- target URL reconstruction must stop inferring HTTPS from Burp scope
- collaborator enablement must be enforced by configuration, not by runtime availability alone
- stop semantics must prevent post-stop request dispatch
- session orchestration must move out of the Swing tab class

### High-Value Cleanup

- replace stringly typed attack names with an enum or descriptor object
- remove duplicated path extraction and parameter parsing utilities
- consolidate logging and progress reporting
- remove dead fields and unused constructor parameters
- isolate filter state from Swing components

## Testing Strategy

- Keep Montoya API usage behind interfaces and mock those interfaces in unit tests.
- Add golden tests for request rewrite operations because these are the highest-risk regressions.
- Treat payload templates as test fixtures and verify expansion counts and placeholder behavior.
- Add lifecycle tests that assert `stop` and `close` are terminal and idempotent.

## Definition of Done

- A closed session cannot continue sending requests.
- A stopped run cannot send additional requests after stop is acknowledged.
- Attack execution uses one shared execution pipeline.
- UI classes are under 300 lines unless there is a documented exception.
- Core request mutation logic is covered by automated tests.
- New attacks can be added through the registry without touching session orchestration.
