# Phase: Scoped ReqProof Stabilization -- Current Warning Disposition

Date: 2026-06-20

## Goal

Track the current truthful baseline on the path to full Tyk ReqProof onboarding
with zero audit warnings. The current state is not accepted as complete; it is
the honest backlog after removing known false evidence. The audit policy remains
strict:

- `project.audit.fail_level: warn`
- `project.workflow.fail_level: warn`
- `verification_scope_complete` remains enabled and visible
- no waivers
- no warning suppression
- no obligation suppressions
- no fake `// MCDC` witnesses
- no no-op trigger-false witnesses

Most production Go files are still visible as out of scope until they have real
product requirements, traces, and evidence. The path to zero warnings is full
onboarding, not narrowing the audit or hiding the warning.

## Current Audit Snapshot

Command:

```sh
proof audit --format markdown --max-findings 20
```

Result:

```text
Errors: 0
Warnings: 2
```

The remaining warnings are intentionally not hidden. Each is classified below by
the honest disposition required to close it.

## Warning Disposition

| Check | Current finding | Disposition | Why it remains |
| --- | --- | --- | --- |
| `verification_scope_complete` | 142/447 declared production source files covered | full-scope onboarding required | The current requirement hierarchy covers the scoped policy/helper slice only. Broad packages such as remaining `apidef`, `gateway`, `storage`, `rpc`, certificates, plugins, and coprocess need product-level STK/SYS hierarchy and package onboarding waves before the scope warning can honestly clear. |
| `mcdc_coverage` | 52/385 uncovered rows across 29 partial requirements | ReqProof tooling gap and model refinement required | Remaining rows are trigger-false/no-action rows from implication-shaped requirements such as `!operation_requested | result_returned`, plus paired invariant-violation rows whose positive row set is still incomplete while the trigger-false row is unresolved. Direct helper tests cannot honestly prove the no-action row because calling the helper is the request. |

Closed during this pass:

- `authored_delta_expected` was closed by real impact reviews for
  `internal/policy/apply.go` and related `internal/policy/util.go` ownership.
- `spec_lint_status_vs_review` was closed for `SW-REQ-007` and `SW-REQ-008`
  after explicit chat delegation from `human:buger`; the approval comments
  state that MC/DC gaps remain tracked separately.
- `suspect_clean` was closed after explicit chat delegation from `human:buger`
  to review the current suspect trace set; the trace review does not waive
  MC/DC coverage or product KnownIssues.

## MC/DC Evidence Policy For This Phase

Rows are handled using the following rule:

- A real executable path gets a real `// MCDC` row only when the test body
  actually drives and asserts that behavior.
- Trigger-false/no-action rows remain red unless there is concrete no-action
  evidence or ReqProof gains an explicit row-level no-action evidence mechanism.
- `//mcdc:ignore` is allowed only for true invariant or guarantee violation
  rows after the positive rows are already witnessed.
- Any ignore must include a clear category and reason.
- A real product defect becomes a KnownIssue, not an assumption or waiver.

The trigger-false/no-action witness gap is tracked upstream:

- `probelabs/reqproof#257` -- Require explicit no-action evidence on
  trigger-false MC/DC row witnesses.

## Current MC/DC Backlog Classification

The current 52 uncovered MC/DC rows are intentionally left visible. They fall
into two closure groups:

1. Trigger-false/no-action rows: leave red until there is real no-action
   evidence, requirement refinement, or the ReqProof mechanism from
   `probelabs/reqproof#257`.
2. Paired invariant-violation rows: leave red while the paired trigger-false
   row is unresolved, because the requirement's positive row set is incomplete.

Some trigger-true violation rows may later get real executable witnesses, and
some trigger-false rows may become caller-level no-action tests. This table does
not mark them green in advance. It records the current honest state: no backlog
row has enough evidence to close today, and no backlog row currently requires a
new product KnownIssue.

| Requirement | Missing row shape | Classification | Current disposition |
| --- | --- | --- | --- |
| `SW-REQ-001` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-003` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-004` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-005` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-006` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-081` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-082` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-083` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-084` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-085` | `requested=F,preserved=F => TRUE`; `requested=T,preserved=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-088` | `requested=F,preserved=F => TRUE`; `requested=T,preserved=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-089` | `requested=F,enforced=F => TRUE`; `requested=T,enforced=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-095` | `requested=F,reported=F => TRUE`; `requested=T,reported=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-098` | `requested=F,scoped=F => TRUE`; `requested=T,scoped=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-100` | `requested=F,returned=F => TRUE`; `requested=T,returned=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-103` | `requested=F,result=F => TRUE`; `requested=T,result=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-108` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-109` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SYS-REQ-110` | `requested=F,determined=F => TRUE`; `requested=T,determined=F => FALSE` | trigger-false plus paired invariant violation | Leave red until no-action evidence or model refinement exists. |
| `SW-REQ-007` | `identity_requested=F,identifier_available=T,identifier_valid=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SW-REQ-008` | `store_requested=F,lookup_returned=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-080` | `api_list_requested=F,api_list_result_returned=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-091` | `validation_requested=F,path_within_target=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-093` | `validation_requested=F,component_accepted=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
| `SYS-REQ-102` | `operation_requested=F,operation_confined=F => TRUE` | trigger-false/no-action only | Leave red until a caller-level no-action witness or requirement refinement exists. |
The earlier invariant-only candidates `SYS-REQ-096`, `SYS-REQ-097`,
`SYS-REQ-099`, and `SYS-REQ-101` were closed with narrow defensive
`//mcdc:ignore` rows after `proof mcdc show` confirmed their positive rows were
already witnessed. No refused, stale, or dangling MC/DC exemptions remain.
`SYS-REQ-092` was closed with real executable evidence: safe archive paths are
presented and accepted, proving `unsafe_archive_path_presented=F` and
`unsafe_archive_path_rejected=F`.

Sub-agent cross-check on 2026-06-19 reached the same row-level classification
for the original backlog and found no remaining missing row that looked like a
new product KnownIssue. Existing KnownIssue-covered rows were already witnessed
rather than part of this backlog.

## Current Known Issues To Keep Visible

The current audit reports eight active KnownIssues. They are intentionally
visible product or platform debts, not assumptions:

- `KI-MODEL-DELETE-LEGACY-LOOKUP`
- `KI-OSUTIL-SYMLINK-ESCAPE`
- `KI-POLICY-APPLY-NONATOMIC-MALFORMED-PARTITION`
- `KI-POLICY-APPLY-NONATOMIC-ORG-MISMATCH`
- `KI-POLICY-APPLY-PARTIAL-MULTIPOLICY-ERROR`
- `KI-POLICY-SHARED-SESSION-RACE`
- `KI-SANITIZE-MALFORMED-PERCENT`
- `KI-SANITIZE-WINDOWS-VOLUME-PATH`

This phase does not fix or close KnownIssues. Existing fixed-status
KnownIssues, if present in `.proof/known-issues`, are historical records from
earlier repair work. The active scoped stabilization posture is only that
currently open product debts stay visible and are not converted into
assumptions, waivers, or MC/DC ignores.

KnownIssue evidence freshness refresh is also outside this phase. As of this
snapshot, `proof known-issue check` reports stale freshness metadata for
historical evidence manifests after nearby proof/test files changed. That is a
separate evidence-refresh/review activity, not a reason to mark product issues
fixed or to hide them from the current strict audit.

## Recent Scope Increments

- `SW-REQ-080` onboarded `apidef/api_definitions.go` with focused evidence for
  Classic API definition core data-model helpers, compatibility encode/decode,
  matcher/template helpers, default shape construction, and event-handler scan
  conversion. This increment does not close the full-scope warning; it moves the
  visible production coverage baseline from 127/447 to 128/447.
- `SW-REQ-081` onboarded `apidef/importer/blueprint.go` with focused evidence
  for Apiary Blueprint JSON loading, error handling, resource/method/header
  conversion, mock versus non-mock action selection, status fallback, version
  insertion, and API-definition proxy/versioning shape. This increment also
  fixes local Blueprint conversion drift where multiple resources and response
  headers were not fully preserved. It moves the visible production coverage
  baseline from 128/447 to 129/447.
- `SW-REQ-082` onboarded `apidef/importer/importer.go` with focused evidence
  for source dispatch across Apiary Blueprint, Swagger, and WSDL importers,
  fresh importer allocation, deterministic returned importer types, and
  unsupported source errors. It moves the visible production coverage baseline
  from 129/447 to 130/447.
- `SW-REQ-083` onboarded `apidef/importer/swagger.go` with focused evidence for
  Swagger JSON loading, error handling, method/path conversion, deterministic
  whitelist and track-endpoint ordering, empty-path skipping, version insertion,
  and API-definition proxy/versioning shape. This increment also fixes local
  Swagger conversion drift where map iteration could reorder converted paths or
  methods and paths with no methods were emitted as empty whitelist entries. It
  moves the visible production coverage baseline from 130/447 to 131/447.
- `SW-REQ-084` onboarded `apidef/importer/wsdl.go` with focused evidence for
  WSDL 1.1 loading, malformed-root and WSDL 2.0 rejection, SOAP/HTTP binding
  conversion, per-importer port mapping isolation, wildcard rewrite conversion,
  malformed service-shape errors, version insertion, and API-definition
  proxy/versioning shape. This increment also fixes local WSDL conversion drift
  where parsed binding and selected port state could leak across importer
  instances and malformed service shapes could panic. It moves the visible
  production coverage baseline from 131/447 to 132/447.
- `SW-REQ-085` onboarded `apidef/migration.go` with focused evidence for
  Classic API definition version splitting, endpoint method-action migration,
  cache migration, authentication config pruning, compatibility flag migration,
  scope/response-processor migration, global rate-limit and IP access-control
  migration, and OAS-origin disabled default initialization. This increment is
  scoped to local data-shape migration helpers and does not close full API
  lifecycle migration evidence. It moves the visible production coverage
  baseline from 132/447 to 133/447.
- `SW-REQ-086` onboarded `apidef/notifications.go` with focused evidence for
  notification manager wire fields, bounded HTTP client construction, empty URL
  and retry-limit boundaries, JSON POST request construction, fixed headers,
  successful delivery handling, and handled local send failures. This increment
  is scoped to local notification helper control flow and does not claim durable
  external delivery. It moves the visible production coverage baseline from
  133/447 to 134/447.
- `SW-REQ-087` onboarded `apidef/oas/authentication.go` with focused evidence
  for OAS authentication helper validation, security-scheme import,
  identity-provider precedence, authentication sources and signatures, scope
  mapping, HMAC/OIDC conversion, custom key lifetime and certificate auth,
  custom plugin authentication, authentication plugin, and ID-extractor
  conversion. This increment is scoped to local OAS/Classic data-shape
  conversion and does not claim runtime authentication enforcement. It moves
  the visible production coverage baseline from 134/447 to 135/447.
- `SW-REQ-088` onboarded `apidef/oas/default.go` with focused evidence for
  default x-tyk-api-gateway shape construction, server-variable substitution
  and URL validation errors, query override parsing, authentication-source and
  security-scheme import coordination, and local operation cleanup. This
  increment is scoped to local OAS default-extension helper behavior and does
  not claim full OAS import or gateway runtime execution. It moves the visible
  production coverage baseline from 135/447 to 136/447.
- `SW-REQ-089` onboarded `apidef/oas/middleware.go` with focused evidence for
  global middleware conversion, plugin configuration and plugin list
  compatibility, CORS/cache/header/context/traffic-log/request-size/ignore-case
  support shapes, path-level operation middleware, MCP primitive extraction,
  scalar middleware helper conversion, nil optional boundaries, and endpoint
  cache defaulting. This increment is scoped to local OAS middleware
  support-shape conversion and does not claim actual gateway middleware
  execution. It moves the visible production coverage baseline from 136/447 to
  137/447.
- `SW-REQ-090` onboarded `apidef/oas/oas.go` with focused evidence for OAS
  root document extension lifecycle helpers, marshalling and clone behavior,
  typed cache initialization and accessors, server-list helpers, validation and
  normalization coordination, required-field defaulting, selected Classic
  compatibility clearing, and validation-option derivation. This increment is
  scoped to local OAS root document helper behavior and does not claim full OAS
  import/export or gateway runtime execution. It moves the visible production
  coverage baseline from 137/447 to 138/447.
- `SW-REQ-091` onboarded `apidef/oas/operation.go` with focused evidence for
  OAS operation document helper behavior: operation middleware containers,
  local import coordination, ExtendedPaths fill/extract orchestration, regex
  path normalization and operation ID creation, validate-request schema
  conversion and import gating, mock-response conversion and import gating,
  content-type detection, and deterministic mock allow-list sorting. This
  increment is scoped to local OAS operation helper behavior and does not claim
  gateway route matching or runtime middleware execution. It moves the visible
  production coverage baseline from 138/447 to 139/447.
- `SW-REQ-092` onboarded `apidef/oas/security.go` with focused evidence for
  OAS security document helper behavior: standard auth helper shapes,
  import/default/normalization behavior, nested provider support-shape
  conversion, API-key and OAuth security-scheme construction/extraction,
  proprietary-auth classification, OAS/vendor security requirement partitioning
  and recombination, aggregate security fill/extract coordination, JWT
  configuration lookup, and Classic security reset behavior. This increment is
  scoped to local OAS security support-shape conversion and does not claim
  runtime authentication execution. It moves the visible production coverage
  baseline from 139/447 to 140/447.
- `SW-REQ-093` onboarded `apidef/oas/upstream.go` with focused evidence for
  OAS upstream document helper behavior: aggregate upstream fill/extract
  coordination, service-discovery/cache conversion, uptime-test conversion and
  URL normalization, mutual-TLS and certificate-pinning map conversion,
  rate-limit metadata conversion, TLS transport/proxy metadata conversion,
  upstream authentication/request-signing support-shape conversion,
  load-balancing target weight conversion, and preserve-host/trailing-slash
  flag conversion. This increment is scoped to local OAS upstream support-shape
  conversion and does not claim runtime proxying or upstream execution. It
  moves the visible production coverage baseline from 140/447 to 141/447.
- `SW-REQ-094` onboarded
  `apidef/streams/bento/schema/generate_bento_config_schema.go` with focused
  evidence for Bento configuration schema-generation helper behavior: selected
  property/definition copying, supported source extraction, unsupported source
  omission, custom rule application and error wrapping, URI format insertion,
  deterministic JSON file writing, selected CLI help/output handling, and
  controlled malformed-input/output-path errors. This increment is scoped to
  local generator behavior and does not claim Bento schema completeness or
  stream runtime validation. It moves the visible production coverage baseline
  from 141/447 to 142/447.

Future changes that discover real bad behavior should add or update KnownIssues
with reproducing evidence instead of using assumptions, accepted risks, or
requirement ignores.

## Next Honest Closure Paths

1. MC/DC model/tooling path:
   - Do not add no-op tests for trigger-false rows.
   - Refine requirements or variable roles where activation/no-action rows are
     not meaningful executable obligations.
   - Use the upstream ReqProof no-action evidence mechanism when available.

2. Scope onboarding path:
   - Add product capability hierarchy by domain, not by package name.
   - Bring production packages into `verification_scope.include` in batches only
     after real STK/SYS/SW requirements, traces, and tests exist.
   - Recent increments include `pkg/validator` custom-policy-ID validation,
     `dnscache` local DNS cache storage and manager behavior,
     `internal/service/core` upstream-auth request-context helpers, and
     `apidef/mcp` embedded MCP schema validation with the local
     `internal/service/gojsonschema` and `internal/errors` facades,
     `internal/errors` diagnostic classification, `internal/oasutil` OAS
     path/server helpers, the `user` MCP access-right data model,
     `pkg/schema` OAS visitor/unicode-escape helpers, the
     `internal/middleware` custom middleware enablement helper, the
     `internal/httputil/accesslog` access-log field filter and record helper, the
     `apidef/oas` extension header helper, and the `apidef/oas` MCPPrimitive
     helper shape, the `apidef/oas` readable-duration alias, the
     `apidef/oas` error-override shape helpers, the `apidef/oas` schema example
     extraction helper, the `apidef/oas` internal endpoint shape helper, the
     `apidef/oas` endpoint tracking shape helper, the `apidef/oas` utility
     helper shapes, the `apidef/oas` deprecated-wrapper conversion helper, the
     `apidef/oas` Tyk streaming extension shape, the `apidef/oas` event-handler
     helper shapes, the `apidef/oas` server-regeneration helper shapes, the
     `apidef/oas` validator helper shapes, the `apidef/oas` root extension
     helper shapes, the `apidef/oas` server model helper shapes, and the
     `apidef/oas` URL rewrite helper shapes, and the `apidef/oas` MCPPrimitive
     build-mode guard helpers, the `internal/reflect` support helpers, the
     `pkg/errpack` typed diagnostic error helpers, the
     `internal/service/newrelic` observability adapter helpers, and the
     `apidef/adapter` import interface, GraphQL utility helpers, GraphQL
     config adapter helpers, AsyncAPI adapter helper, OpenAPI adapter
     helper, `apidef/adapter/gqlengineadapter` utility helpers, and the
     GraphQL proxy-only, supergraph, and universal-data-graph engine adapter
     helpers, plus the engine v3 proxy-only and supergraph adapter helpers.
     They reduce the visible scope gap but do not change the remaining warning
     disposition. The engine v3 utility and universal-data-graph adapter
     helpers are also now covered.
