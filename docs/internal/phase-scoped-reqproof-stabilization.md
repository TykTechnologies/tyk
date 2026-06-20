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
| `verification_scope_complete` | 162/447 declared production source files covered | full-scope onboarding required | The current requirement hierarchy covers the scoped policy/helper slice only. Broad packages such as remaining `apidef`, `gateway`, `storage`, `rpc`, certificates, plugins, and coprocess need product-level STK/SYS hierarchy and package onboarding waves before the scope warning can honestly clear. |
| `mcdc_coverage` | 52/433 uncovered rows across 29 partial requirements | ReqProof tooling gap and model refinement required | Remaining rows are trigger-false/no-action rows from implication-shaped requirements such as `!operation_requested | result_returned`, plus paired invariant-violation rows whose positive row set is still incomplete while the trigger-false row is unresolved. Direct helper tests cannot honestly prove the no-action row because calling the helper is the request. |

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
- `SW-REQ-095` onboarded `apidef/streams/bento/validator.go` with focused
  evidence for Bento configuration validator helper behavior: one-time embedded
  schema loading, default validator construction, valid document acceptance,
  validation error aggregation, malformed-document error propagation, and
  enable-all-experimental accept-all behavior. This increment is scoped to
  local validator helper behavior and does not claim Bento schema completeness
  or stream runtime validation. It moves the visible production coverage
  baseline from 142/447 to 143/447.
- `SW-REQ-096` onboarded `apidef/streams/validator.go` with focused evidence
  for Tyk Streams OAS validator helper behavior: embedded stream OAS/Tyk
  extension schema loading, version resolution and default-version selection,
  OAS object/template validation, template required-field relaxation,
  stream-scoped Bento validation errors, and enable-all/disable-validator
  bypasses. This increment is scoped to local validator helper behavior and
  does not claim embedded schema completeness, Bento schema completeness, stream
  runtime execution, or final client-visible validation behavior. It moves the
  visible production coverage baseline from 143/447 to 144/447.
- `SW-REQ-097` onboarded `apidef/validator.go` with focused evidence for
  Classic API definition validator helper behavior: validation result state,
  rule dispatch, duplicate GraphQL data-source names, auth-source enablement,
  IP/CIDR syntax checks, hard-timeout boundaries, upstream-auth configuration,
  and load-balancing target checks. This increment is scoped to local validator
  helper behavior and does not claim gateway request admission, runtime auth
  execution, load-balancer traffic distribution, invalid-index `ErrorAt`
  behavior, or final client-visible behavior. It moves the visible production
  coverage baseline from 144/447 to 145/447.
- `SW-REQ-098` onboarded `certs/manager.go` with a new certificate lifecycle
  stakeholder/system/software chain and focused evidence for local certificate
  manager helper behavior: PEM parsing, certificate/public-key ID derivation,
  malformed/expired/duplicate/mismatched material rejection, private-key
  encryption before storage, list modes, raw retrieval, org indexes, cache
  flushing, public-key helpers, metadata extraction, masked IDs, and CA pool
  assembly. This increment is scoped to local certificate lifecycle support and
  does not claim TLS handshake enforcement, runtime mTLS request
  authentication, upstream TLS validation, live MDCB availability, external
  storage durability, certificate expiry monitoring, or gateway request
  admission. It moves the visible production coverage baseline from 145/447 to
  146/447.
- `SW-REQ-099` onboarded `checkup/checkup.go` with a new startup checkup
  stakeholder/system/software chain and focused evidence for local startup
  configuration diagnostic behavior: warnings for insecure configuration
  allowance, deprecated health checks, missing global session lifetime, retained
  default gateway/node secrets, analytics defaulting for pool size, records
  buffer size, and storage expiration, public `Run` orchestration, and host
  CPU/file-descriptor probe execution without mutation claims. This increment is
  scoped to local startup checkup helper behavior and does not claim OS resource
  tuning, log transport delivery, operator remediation, gateway request
  admission, analytics pipeline durability, or final client-visible behavior. It
  moves the visible production coverage baseline from 146/447 to 147/447.
- `SW-REQ-100` onboarded `cli/bundler/bundler.go` with a new plugin bundle CLI
  stakeholder/system/software chain and focused evidence for local bundle
  command behavior: command registration, manifest loading, malformed JSON and
  validation errors, missing referenced file rejection, checksum calculation,
  unsigned ZIP bundle creation, RSA private-key signing, and verifiable base64
  signature storage. This increment is scoped to local CLI bundle construction
  support and does not claim gateway-side signature verification, plugin
  loading, plugin execution, bundle distribution, persistence, hot reload, or
  final gateway request behavior. It moves the visible production coverage
  baseline from 147/447 to 148/447.
- `SW-REQ-101` onboarded `cli/importer/importer.go` with a new CLI import
  command stakeholder/system/software chain and focused evidence for local
  command wrapper behavior: command registration and flag binding, create/API
  version input validation, valid WSDL service:port mapping, local API
  definition JSON load/decode behavior, Blueprint/Swagger/WSDL loader
  selection and missing-file errors, and printed API definition JSON formatting
  without empty BSON-only IDs. This increment is scoped to local CLI import
  support and does not claim full Blueprint, Swagger, or WSDL conversion
  correctness, gateway API loading, route generation, request matching, gateway
  request admission, persistence, analytics, or final client-visible runtime
  behavior. It moves the visible production coverage baseline from 148/447 to
  149/447.
- `SW-REQ-102` onboarded `cli/linter/linter.go` with a new CLI configuration
  linter stakeholder/system/software chain and existing table-driven evidence
  for local config lint behavior: malformed JSON and config decode errors,
  schema warnings for unknown fields/enums/nested shapes, legacy `Monitor`
  normalization, custom path and host-without-port format warnings, accepted
  empty/default/null-object cases, and local config rewrite through
  `config.WriteConf`. This increment is scoped to local CLI lint support and
  does not claim full gateway configuration semantics, gateway startup
  behavior, persistence, network binding, analytics, or final client-visible
  runtime behavior. It moves the visible production coverage baseline from
  149/447 to 150/447.
- `SW-REQ-103` onboarded `config/config.go` with a new gateway configuration
  stakeholder/system/software chain and existing config tests for local
  configuration behavior: default values and `WriteDefault` output, ordered
  file layering and missing-file errors, environment variable overrides through
  envconfig/custom loaders, event trigger migration, cert/custom-secret/
  port-whitelist/labs decoders, ignored-IP analytics decisions, certificate
  expiry monitor defaults and overrides, and tracing/OpenTelemetry JSON/env
  parsing and round trips. This increment is scoped to local configuration
  helper support and does not claim full gateway runtime interpretation of
  every configuration field, network binding, storage connectivity, analytics
  delivery, tracing export delivery, API loading, request admission, or final
  client-visible runtime behavior. It moves the visible production coverage
  baseline from 150/447 to 151/447.
- `SW-REQ-104` onboarded `config/external_service.go` with a new external
  service configuration stakeholder/system/software chain and existing
  table-driven config tests for local helper behavior: JSON field preservation
  for global proxy and service-specific mTLS fields, zero and partial
  configuration shapes, service type constants, certificate-store JSON fields,
  mTLS validation for disabled, file-based, certificate-store, CA-only,
  conflicting, and incomplete configurations, and file-based versus
  certificate-store helper classification. This increment is scoped to local
  external service configuration helper support and does not claim proxy
  transport behavior, certificate loading, TLS handshake enforcement, outbound
  service connectivity, storage/OAuth/webhook/health/discovery delivery, or
  final gateway runtime behavior. It moves the visible production coverage
  baseline from 151/447 to 152/447.
- `SW-REQ-105` onboarded `config/development.go` and
  `config/development_off.go` with a new development configuration
  stakeholder/system/software chain, tagged dev/non-dev config tests, and
  explicit `-tags dev` build/test/vet gates in `proof.yaml`. The evidence
  covers dev builds falling back to default storage when custom rate limiter
  storage is disabled or absent, dev builds selecting configured rate limiter
  storage when enabled and present, and release builds always using default
  storage. This increment is scoped to local build-tag-specific configuration
  helper support and does not claim rate limiter algorithm behavior, Redis
  connectivity, distributed storage behavior, gateway request admission, or
  final client-visible runtime behavior. It moves the visible production
  coverage baseline from 152/447 to 154/447.
- `SW-REQ-106` onboarded `config/private.go` with a new private
  configuration stakeholder/system/software chain and a focused table-driven
  config test for local OAuth token purge interval behavior: one-hour default
  duration when the private interval is absent and configured second-based
  durations when present. This increment is scoped to local private
  configuration helper support and does not claim OAuth token storage, purge
  execution, scheduler behavior, customer JSON exposure, or final gateway
  runtime behavior. It moves the visible production coverage baseline from
  154/447 to 155/447.
- `SW-REQ-107` onboarded `config/rate_limit.go` with a new rate-limit
  configuration stakeholder/system/software chain and a focused table-driven
  config test for local `RateLimit.String` behavior: default distributed Redis
  description, transaction versus pipeline wording, fixed-window precedence,
  Redis rolling selection, Sentinel selection, distributed Sentinel selection,
  and smoothing wording. This increment is scoped to local rate-limit
  description helper support and does not claim request throttling, quota
  enforcement, Redis connectivity, header emission, or final gateway runtime
  behavior. It moves the visible production coverage baseline from 155/447 to
  156/447.
- `SW-REQ-108` onboarded `config/opentracing_custom_env_loader.go` with a new
  OpenTracing configuration stakeholder/system/software chain and focused
  config tests for local tracing option decode and environment override
  behavior: Zipkin and Jaeger env overrides, JSON/YAML-compatible option
  decoding, unrelated tracer no-op behavior, and invalid environment value
  errors. This increment is scoped to local tracing configuration helper
  support and does not claim tracer initialization, trace export delivery,
  collector connectivity, runtime sampling correctness, panic recovery for
  unsupported non-serializable in-memory Go values, or final gateway runtime
  behavior. It moves the visible production coverage baseline from 156/447 to
  157/447.
- `SW-REQ-109` onboarded `config/util.go` with a new configuration utility
  stakeholder/system/software chain and focused config tests for local utility
  behavior: discovered `tyk.conf` loading, environment fallback when the config
  file is absent, default cloning with environment overrides, file discovery
  success and not-found errors, and storage host address assembly precedence.
  This increment is scoped to local configuration utility helper support and
  does not claim full gateway startup behavior, all configuration field
  semantics, storage connectivity, Redis dialing, filesystem permission
  recovery outside local file discovery, or final gateway runtime behavior. It
  moves the visible production coverage baseline from 157/447 to 158/447.
- `SW-REQ-110` onboarded `common/option/option.go` with a new reusable option
  builder stakeholder/system/software chain and focused table-driven tests for
  local generic helper behavior: `New` preserves supplied option slices,
  `Build` returns a pointer to a copied base value, empty option collections
  preserve the base value, and option functions apply in order. This increment
  is scoped to local option builder mechanics and does not claim the domain
  behavior of API definition versioning, OAS builders, gateway API loading,
  mock response middleware, or any other downstream option consumer. It moves
  the visible production coverage baseline from 158/447 to 159/447.
- `SW-REQ-111` onboarded `coprocess/dispatcher.go` with a new coprocess
  dispatcher stakeholder/system/software chain and a focused table-driven
  compile-time conformance test for the local `coprocess.Dispatcher` interface
  surface. This increment is scoped to method availability for message
  dispatch, context-aware dispatch, event dispatch, object dispatch, module
  loading, middleware cache handling, and reload operations. It does not claim
  gRPC transport behavior, Python runtime loading, Lua bundle execution,
  gateway middleware effects, generated protobuf serialization behavior, or
  downstream dispatcher implementation correctness. `coprocess/grpc/doc.go` and
  `coprocess/python/doc.go` remain omitted because their packages currently
  fail to load while the unrelated `internal/build` deletion is present. It
  moves the visible production coverage baseline from 159/447 to 160/447.
- `SW-REQ-112` onboarded `ctx/ctx.go` with a new request context
  stakeholder/system/software chain and focused tests for context key
  uniqueness, session/auth-token storage and retrieval, API/OAS definition
  clone retrieval, error-classification storage, JSON-compatible session
  fallback retrieval, nil-session panic behavior, and table-driven JSON-RPC/MCP
  metric getter defaults and typed values. The pass also records
  `KI-CTX-SESSION-HASH-OVERRIDE` for the confirmed defect where a single
  optional `SetSession(..., hashKey)` override is ignored and the global
  `HashKeys` setting is used instead. This increment is scoped to local request
  context helper mechanics and does not claim gateway middleware admission
  behavior, downstream plugin behavior, storage persistence, access-control
  decisions, or final request handling. It moves the visible production
  coverage baseline from 160/447 to 161/447.
- `SW-REQ-113` onboarded `ee/errors.go` with a new enterprise error
  stakeholder/system/software chain and a focused table-driven sentinel error
  test for `ErrActionNotAllowed`. This increment is scoped to local sentinel
  availability and does not claim stream middleware behavior, upstream
  authentication behavior, license enforcement behavior, or final gateway
  request handling. It moves the visible production coverage baseline from
  161/447 to 162/447.
- `SW-REQ-114` onboarded `ee/middleware/streams` with a new enterprise streams
  stakeholder/system/software chain and focused package evidence for OAS stream
  config extraction, request-scoped variable replacement, HTTP path extraction
  and matching, manager analytics fallback behavior, unsafe-component filtering
  and allow-listing, Bento structured log translation and malformed-log errors,
  and stream start/stop terminal outcomes. The system formula is a local
  terminality invariant, with the unreachable non-terminal invariant-violation
  row documented rather than covered by a fake runtime witness. This increment
  is scoped to local enterprise stream middleware helper mechanics and does not
  claim external Bento delivery correctness, upstream authentication behavior,
  gateway API loading, network transport delivery, persistence, or final
  client-visible gateway behavior. It moves the visible production coverage
  baseline from 162/447 to 169/447.

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
