# Tyk Requirements Layering Strategy

<!-- documents SW-REQ-002 -->

This branch started as policy-engine proof work. Before expanding coverage to
more packages, the requirement model must be reshaped around gateway behavior,
not around internal package inventory.

## Governing Rule

`proof help spec-layering` defines the levels:

- `STK-REQ`: user, operator, safety, support, business, or regulatory intent.
  Stakeholder requirements must not name private packages or functions.
- `SYS-REQ`: externally observable gateway behavior that remains meaningful if
  the implementation is replaced.
- `SW-REQ`: component-owned design behavior: packages, modules, algorithms,
  persistence models, code invariants, and implementation-specific obligations.
- `INT-REQ`: one caller/callee boundary, schema, API, event, or compatibility
  contract. INT requirements require real integration evidence.

The proof-slice rule is equally important: one proof slice should be one
component, one coherent requirement set, and one contract shape matching a real
code boundary. Do not invent fake components or raise budgets to hide modeling
problems.

## Target Tyk Shape

Tyk should use this configured hierarchy when the migration is ready:

```yaml
specs:
  - path: specs/stakeholder
    prefix: STK-REQ
    type: stakeholder
  - path: specs/system
    prefix: SYS-REQ
    type: system
    parent_spec: specs/stakeholder
  - path: specs/software
    prefix: SW-REQ
    type: subsystem
    parent_spec: specs/system
  - path: specs/integration
    prefix: INT-REQ
    type: integration
    parent_spec: specs/system
    cross_component: true
```

Do not enable an empty level in `proof.yaml`: `levels_connected` correctly
fails when a configured layer has no requirements. `specs/software` is now
enabled because real SW decompositions exist. Add `specs/integration` only
with a real interface contract and direct integration evidence.

## Gateway Story Map

The top-level stakeholder stories should describe gateway outcomes:

- API traffic authorization: authenticated consumers receive exactly the
  access rights, deny decisions, quota, rate, and endpoint permissions assigned
  by current policy state.
- Policy lifecycle and reload safety: policy changes take effect without stale
  session state, cross-organization leakage, or partial updates on failure.
- Request routing and transformation: loaded API definitions produce stable
  routing, middleware, URL matching, and upstream behavior.
- Operational observability: events, analytics, tracing, health reporting, and
  logs preserve the information operators need to diagnose requests and
  gateway state.
- Configuration and bundle safety: API definitions, policies, bundles, and
  generated identifiers are loaded from constrained paths and parsed with
  bounded, explicit failure behavior.
- Runtime resilience: hot-path helpers remain deterministic, bounded,
  panic-free for malformed input, and race-safe under concurrent requests.

These are STK/SYS concerns. Internal packages are evidence or SW decomposition,
not stories on their own.

## Strict Baseline

Strict audit policy is now intentionally warning-gated:

```yaml
audit:
  fail_level: warn
  scope: full
workflow:
  fail_level: warn
verification_scope:
  completeness:
    production_include:
      - "**/*.go"
```

The current state is not repo-wide green. With production Go completeness
enabled, `proof workflow check --stage spec --format json` reports one warning:
`verification_scope_complete` covers 24 of 495 declared production Go files.
`proof scope --format json` reports 51 in-scope source files, 27 in-scope test
files, 482 in-scope functions, 332 in-scope test functions, 912 out-of-scope
source files, and 9664 out-of-scope functions. The two counts are different
because the workflow completeness check counts declared production Go files,
while `proof scope` reports the full enabled source/test scan.

A one-off repo-wide implementation check also shows why scope expansion must be
deliberate rather than a single manifest flip: `lint_clean` reports thousands
of untraced functions and `orphan_code_clean` reports thousands of code
functions without requirement annotations under `--verification-scope '**'`.
Those are real onboarding gaps, not warnings to suppress.

As of commit `d26158efb`, the full strict audit is not green either:
`proof audit --format markdown --max-findings 0` reports 0 errors and 2
warnings. The blocking warnings are `verification_scope_complete` and
`suspect_clean`. The enabled-slice implementation stage is clean, validation is
clean, and targeted documentation, acceptance, MC/DC, and KnownIssue checks are
clean. The remaining `suspect_clean` warning requires trace review of 35 stale
links; it should be handled as a human trace review packet, not by spoofing a
human reviewer.

The local worktree also currently has `internal/build` deleted while runtime
packages such as `goplugin`, `cli`, `cli/version`, and `gateway/version.go`
import `github.com/TykTechnologies/tyk/internal/build`. Until that build
surface is restored or explicitly excluded with rationale, a ReqForge-style
`go build ./...` command is not an honest gate for this branch. The proof
build/test commands must therefore expand by verified package waves.

The target goal should be stated as a staged strictness migration, not as
"make the current slice green":

1. Preserve the current enabled-slice strictness: no validation errors, no
   evidence warnings, no waivers, no suppressions, and warning-gated audit.
2. Restore or replace broken production build surfaces so `go list ./...` and
   repo-wide build checks are meaningful.
3. Expand verification scope by product capability, adding STK/SYS/SW/INT
   requirements only where the layer is justified by `proof help
   spec-layering`.
4. Add annotations only when the named test directly proves the named
   obligation and level; otherwise add the test first or leave the claim out.
5. Keep product defects as KnownIssues until fixed or formally dispositioned by
   humans; do not weaken requirements to fit current behavior.
6. End state: `proof validate`, every workflow stage, and full audit pass at
   `fail_level: warn` with production Go completeness green.

## Product Capability Map

The repo-wide migration should expand by product capability, not by directory
alphabet:

| Capability group | Main packages | Requirement shape |
| --- | --- | --- |
| Gateway traffic and middleware runtime | `gateway`, `request`, `tcp`, `dnscache` | STK for request handling, routing, auth, rate/quota, transforms, protocol behavior. SYS split by HTTP proxy, TCP/TLS proxy, middleware ordering, request identity, DNS cache, streaming, GraphQL, JSON-RPC, and MCP behavior. |
| API definition lifecycle | `apidef`, `apidef/oas`, `apidef/importer`, `apidef/adapter`, `gateway`, `cli/importer` | STK for creating, validating, importing, migrating, loading, and serving Classic/OAS/MCP/Streams APIs. SYS for schema validation, OAS conversion, import adapters, route generation, loader/reload behavior. |
| Configuration and startup | `config`, `cli`, `gateway`, `dnscache`, `storage` | STK for deterministic startup and configuration. SYS for defaults, environment precedence, file round trips, external services, storage configuration, and DNS cache configuration. |
| Auth, sessions, policies, and identity | `gateway`, `user`, `apidef`, `storage`, `request`, `certs`, `internal/policy`, `internal/rate` | Extend the current policy model to cover session serialization, custom policy metadata, key/certificate binding, auth modes, real-IP handling, and quota/rate state. |
| Certificates and TLS material | `certs`, `gateway`, `config`, `storage`, `rpc`, `internal/certcheck`, `internal/certusage` | STK for certificate/key lifecycle and TLS enforcement. SYS for add/list/delete/cache, certificate ID scoping, mTLS client auth, upstream cert validation, expiry monitoring, and control-plane retrieval. |
| Persistence, Redis, analytics, quota state | `storage`, `storage/kv`, `gateway`, `rpc`, `user`, `internal/rate` | STK for durable/runtime state correctness. SYS for storage handler contracts, Redis operations, rate/quota windows, pubsub/reload signals, analytics purge, OAuth/session persistence, Vault/Consul KV. |
| Control-plane and RPC sync | `rpc`, `gateway`, `storage`, `certs`, `config` | STK for worker/control-plane consistency. SYS for RPC client lifecycle, dispatcher calls, backup storage behavior, DNS-aware reconnect, group sync, and key/policy/cert pull-through caching. |
| Extensibility and plugins | `coprocess`, `goplugin`, `gateway`, `apidef`, `cli/bundler`, `cli/plugin` | STK for custom plugin execution. SYS for Go plugin symbol loading, bundle build/verification, coprocess protocol objects, gRPC/Python/Lua/JS hooks, hook ordering, and loop protection. |
| Observability and external services | `gateway`, `config`, `rpc`, `storage`, `internal/otel`, `internal/otel/apimetrics`, `internal/service/newrelic` | Extend observability requirements to cover webhooks, dashboard registration/recovery, host checker, service discovery, external OAuth/JWK/introspection, analytics, event metadata, trace spans, and metric dimensions. |
| CLI and operator tooling | `cli`, `cli/bundler`, `cli/linter`, `cli/version`, `apidef`, `goplugin`, `config` | STK for operator-facing commands. SYS for command parsing, lint/import output, bundle contents/signature behavior, plugin compiler naming, and version output. |

Likely SW-only helpers should remain under consuming SYS stories unless a
product contract makes them observable: `request`, `user`, `dnscache`
internals, low-level `goplugin`, generated `coprocess` protobufs, `storage`
mocks, `certs` mocks, `internal/cache`, `internal/memorycache`,
`internal/redis`, `internal/scheduler`, `internal/oasutil`,
`internal/service/gojsonschema`, `internal/reflect`, `internal/service/core`,
and provider wrappers. Do not create standalone STK/SYS stories for generic
helpers.

Generated or test-support packages need explicit exclusion or separate
treatment before they enter production completeness: `internal/rate/mock`,
`internal/graphengine/gomock_reflect_3503306920`, generated mock files, and
packages imported only from tests such as `internal/oasbuilder` and
`internal/debug2`.

## Repo Inventory Snapshot

The repo-wide map should be driven by observed production surface, existing
tests, and product boundaries. A current `go list ./...` inventory is blocked
by the missing `internal/build` package, but it still enumerates the major
packages before failing. The largest production surfaces are:

| Surface | Production Go files | Requirement treatment |
| --- | ---: | --- |
| `gateway` | 147 | Product-facing SYS hub for request handling, auth, middleware ordering, API loading, rate/quota enforcement, observability, protocol handling, TLS, and control-plane behavior. Decompose implementation detail into SW only after the SYS story is stable. |
| `apidef/oas`, `apidef`, `apidef/adapter`, `apidef/importer`, `apidef/mcp`, `apidef/streams` | 50+ | Product-facing API definition lifecycle. SYS owns Classic/OAS/MCP/Streams parsing, conversion, validation, import, and route-generation behavior. Package helpers become SW under those SYS requirements. |
| `internal/graphengine`, `internal/graphql`, `internal/mcp`, `internal/jsonrpc` | 20+ | Protocol capability clusters. SYS owns externally observable request/response and telemetry behavior. SW owns parser/adapter/registry/helper behavior. INT only when a caller/callee boundary is directly tested. |
| `internal/rate`, `internal/rate/limiter`, `internal/rate/model`, `internal/rate/mock` | 19 | Product-facing rate/quota enforcement and storage behavior. Keep mocks/test adapters out of production scope unless a generated or test-support rule explicitly covers them. |
| `storage`, `storage/kv`, `rpc`, `internal/redis`, `internal/cache`, `internal/memorycache` | 26+ | Persistence/control-plane state. SYS owns durability, Redis/keyspace behavior, reload/pubsub, and worker/control-plane sync outcomes. INT candidates need real storage/RPC integration tests. |
| `config`, `dnscache`, `request`, `user` | 18+ | Configuration, request identity, and session state. SYS owns operator-visible startup/config precedence and request/session behavior. Most package invariants are SW under those product behaviors. |
| `certs`, `internal/certcheck`, `internal/certusage` | 7 | Security-critical certificate/TLS lifecycle. SYS owns add/list/delete/cache, expiry, mTLS, and upstream validation behavior; SW owns helper and cache mechanics. |
| `coprocess`, `coprocess/grpc`, `coprocess/python`, `dlpython`, `goplugin` | 20+ | Extensibility and plugin execution. SYS owns hook behavior, bundle/plugin loading, protocol objects, and failure isolation. INT requires direct hook/protocol integration evidence. |
| `internal/otel`, `internal/otel/apimetrics`, `trace`, `trace/jaeger`, `trace/openzipkin`, `internal/service/newrelic`, `log` | 27+ | Observability. SYS owns stable metric/span/log/event fields and failure behavior. SW owns provider adapters and encoding helpers. |
| `cli`, `cli/bundler`, `cli/importer`, `cli/linter`, `cli/plugin`, `cli/version` | 6+ | Operator tooling. SYS owns command behavior and outputs. SW owns helper/build mechanics. `internal/build` must be restored before this can be honestly gated. |

This inventory makes two constraints explicit:

1. `gateway` should not be onboarded as a monolith. It should be sliced by
   capability and backed by focused integration/system tests.
2. Small helper packages should not receive standalone stakeholder stories just
   because they are easy to test. They enter scope through the product behavior
   they implement.

## Domain Slice Map

The initial repo map was checked by three read-only domain scans. Their output
is the starting point for requirement authoring and package onboarding.

### Gateway, API, Auth, And Startup

| Slice | Product capability | Main package groups | Likely STK/SYS claim shape | SW decomposition candidates |
| --- | --- | --- | --- | --- |
| Gateway request handling | Accept, authorize, route, transform, proxy, mock, cache, stream, and observe API traffic. | `gateway`, `request`, `tcp`, `dnscache`, `internal/middleware`, `internal/jsonrpc`, `internal/mcp`, `internal/graphql`, `internal/graphengine` | STK: gateway traffic is routed and enforced according to loaded API, session, and policy state. SYS: listen path/domain/version selection, middleware order, auth allow/deny, URL rewrite, transforms, CORS, mock responses, reverse proxy headers/timeouts, SSE/WebSocket/GraphQL/JSON-RPC/MCP behavior. | Split `gateway` runtime by loader, mux/proxy, middleware family, response handler, and protocol adapter. Keep `request.RealIP`, middleware statuses, low-level caches, and DNS helpers as SW unless tied to request-visible behavior. |
| API definitions | Classic, OAS, MCP, and Streams definitions are parsed, validated, migrated, imported, loaded, and converted into runtime routes. | `apidef`, `apidef/oas`, `apidef/adapter`, `apidef/importer`, `apidef/mcp`, `apidef/streams`, `gateway/api_definition.go`, `gateway/api_loader.go`, `cli/importer`, `cli/linter` | STK: configured APIs expose intended routes/security/middleware and reject invalid definitions. SYS: validation, Classic/OAS fill/extract, migration, import adapters, server regeneration, tag filtering, dashboard/RPC/file loading, duplicate listen-path handling. | `apidef` model/validation, OAS extension mapping, adapter/importer packages. Struct tags, enum constants, `ShouldOmit`, schema loading, and fixture helpers stay SW-only unless runtime behavior is tested. |
| Auth, sessions, policies, and identity | Consumers receive the configured access rights, quota/rate, protocol permissions, key/cert/JWT/basic/OAuth decisions, and session persistence semantics. | `gateway/mw_*auth*`, `gateway/session_manager.go`, `gateway/policy.go`, `user`, `internal/policy`, `internal/rate`, `storage`, `request`, `certs` | STK: authenticated consumers get exactly assigned access and limits; failed auth does not grant access. SYS: key lookup/hash fallback, session JSON compatibility, policy merge, org scoping, quota/rate headers, JWT claims/scope mapping, basic auth, mTLS binding, MCP/JSON-RPC access rights. | `internal/policy.Service`, `user.SessionState`/`Policy`/`APILimit`, `internal/rate/model`, and storage handlers. Existing `reqproof:model` and lemma annotations in `user` are SW/model evidence, not standalone STK/SYS evidence. |
| Config and startup | Gateway starts deterministically from CLI/config/env, initializes services, loads APIs/policies, retries reloads, exposes safe config inspection, and shuts down cleanly. | `main.go`, `gateway/server.go`, `config`, `cli`, `storage`, `dnscache`, `trace`, `internal/otel`, `internal/scheduler`, `rpc` | STK: operators can start and reload gateway with predictable config and safe failure behavior. SYS: config defaults/file/env precedence, secret redaction, storage/TLS/external-service config, startup API/policy retry, runtime reload loop non-blocking behavior, graceful shutdown. | `config.Load`, `FillEnv`, `WriteDefault`, CLI command wiring, gateway startup/reload/shutdown methods. Config decoders and CLI flag globals stay SW unless verified through gateway behavior. |

### State, Control Plane, Certificates, And Rate State

| Slice | Product capability | Main package groups | Likely STK/SYS claim shape | SW decomposition candidates |
| --- | --- | --- | --- | --- |
| Storage and persistence | Gateway preserves API keys, sessions, OAuth data, certificate material, analytics buffers, and operator KV secrets across configured backends. | `storage`, `storage/kv`, `gateway/rpc_storage_handler.go`, `gateway/redis_signals.go` | STK: runtime state remains correct across storage failures/reloads. SYS: storage operations return explicit miss/down behavior, apply prefixes/hashing, publish signed cluster notifications, and support Consul/Vault secret reads. | `storage/mock`, dummy storage variants, and `internal/redis` wrappers stay SW or test support unless a product boundary consumes them. |
| RPC and control-plane sync | Worker gateways stay consistent with MDCB/control plane for API definitions, policies, keyspace changes, certificates, and node status. | `rpc`, `gateway/rpc_storage_handler.go`, `gateway/rpc_backup_handlers.go`, `storage/mdcb_storage.go`, `internal/model/rpc.go` | STK: workers recover and converge after control-plane or DNS disruption. SYS: RPC login/retry/emergency mode, DNS-aware reconnect, keyspace polling, backup load/save, group forced sync. | RPC utils and generated/mock RPC shapes are SW unless used at the boundary. |
| Certificates and TLS | Gateway enforces API mTLS, upstream mTLS, certificate pinning/CN checks, certificate storage, and expiry monitoring. | `certs`, `gateway/cert*.go`, `gateway/mw_certificate_check.go`, `internal/certcheck`, `internal/httpclient`, `internal/certusage` | STK: TLS material is loaded, scoped, validated, monitored, and not bypassed silently. SYS: add/list/delete/cert-pool behavior, mTLS request validation, upstream certificate selection, expiry events/cooldowns, external-service mTLS error handling. | `certs/mock`, `internal/crypto`, and cache mechanics remain SW under certificate lifecycle behavior. |
| Redis, cache, and rate state | Gateway enforces quotas/rate limits and serves response/cache state consistently under Redis/local modes. | `gateway/session_manager.go`, `gateway/mw_rate_limiting.go`, `gateway/mw_redis_cache.go`, `gateway/res_cache.go`, `internal/rate`, `internal/cache`, `internal/memorycache`, `dnscache` | STK: consumers are admitted or blocked according to configured quota/rate/cache state. SYS: Redis sliding-log behavior on storage errors, smoothing allowance updates with locking, cache hit/miss semantics, quota/rate headers. | `internal/rate/limiter`, `internal/cache`, `internal/memorycache`, and `dnscache` internals stay SW until gateway-visible behavior is directly tested. |

### Extensibility, Observability, Protocols, And Tooling

| Slice | Product capability | Main package groups | Likely STK/SYS claim shape | SW decomposition candidates |
| --- | --- | --- | --- | --- |
| Plugins and coprocess extensibility | Execute custom middleware/event hooks via Go plugins, JSVM, Python/Lua/gRPC coprocess, bundles, response hooks, analytics plugins, and loop protection. | `coprocess`, `coprocess/grpc`, `coprocess/python`, `coprocess/lua`, `goplugin`, `dlpython`, `gateway`, `cli/bundler`, `cli/plugin` | STK: operators can extend gateway behavior safely. SYS: hook ordering, request/session mutation, response override, bundle pull/verify/load, plugin symbol loading, gRPC dispatch, loop skipping. | Generated protobufs/bindings, `goplugin` filename construction, `dlpython` loader details, and C headers are SW or generated surfaces, not runtime evidence. |
| Events, metrics, and tracing | Operators receive stable diagnostic event metadata, RED metrics, runtime metrics, resource attributes, trace/span IDs, and provider output. | `internal/event`, `gateway/event_*`, `gateway/sse_*`, `internal/otel`, `internal/otel/apimetrics`, `trace`, `trace/jaeger`, `trace/openzipkin`, `internal/service/newrelic`, `log` | STK: operators can diagnose traffic and gateway state. SYS: event metadata preservation, webhook delivery, metric enable/disable behavior, names/labels/dimensions, cardinality handling, resource attrs, span hierarchy, GraphQL/MCP telemetry. | Context key helpers, dimension builders, provider adapters, trace manager globals, and span attribute constructors stay SW unless exporter-visible behavior is tested. |
| GraphQL, MCP, and JSON-RPC protocols | Protocol APIs route, authorize, validate, execute, and report traffic according to definitions and session rights. | `internal/graphql`, `internal/graphengine`, `apidef/adapter/gqlengineadapter`, `internal/mcp`, `internal/jsonrpc`, `internal/jsonrpc/errors`, `apidef/mcp`, `gateway/mw_graphql*`, `gateway/mw_jsonrpc*`, `gateway/mw_mcp*`, `user` | STK: GraphQL/MCP/JSON-RPC APIs enforce configured access/limits and provide telemetry. SYS: validation failures, engine mode, depth limits, persisted operations, JSON-RPC error envelopes, VEM routing, primitive access control, list filtering, path traversal rejection. | AST visitors, mock execution engines, prefix constants, registries, JSON marshal helpers, and schema-key detection are SW unless paired with gateway request evidence. |
| CLI and operator tooling | Operators validate, import, bundle, inspect, and test gateway artifacts. | `cli`, `cli/bundler`, `cli/importer`, `cli/linter`, `cli/plugin`, `cli/version`, `ci/tests/plugin-compiler` | STK: operator commands produce predictable outputs and failure behavior. SYS: command parsing, lint warnings, import output shape, bundle ZIP/manifest/checksum/signature, plugin load output, version fields. | Kingpin wiring, format checker helpers, importer file loaders, and `os.Exit` branches need subprocess evidence before they become SYS claims. |

## Evidence Sources And Boundaries

The evidence plan must distinguish unit evidence from system or integration
evidence. Candidate sources:

| Capability | Evidence to reuse |
| --- | --- |
| Request routing/proxy/middleware | `gateway/api_loader_test.go`, `gateway/api_definition_test.go`, `gateway/proxy_muxer_test.go`, `gateway/reverse_proxy_test.go`, `gateway/middleware_test.go`, `gateway/mw_oas_validate_request_test.go`, `gateway/mw_url_rewrite_test.go`, `gateway/mw_transform_test.go`, `gateway/mw_mock_response_test.go`, `tests/proxy`, `tests/regression`. |
| API definition model/OAS/import | `apidef/validator_test.go`, `apidef/migration_test.go`, `apidef/api_definitions_test.go`, `apidef/oas/*_test.go`, `apidef/adapter/*_test.go`, `apidef/importer/*_test.go`, `apidef/mcp/validator_test.go`, `apidef/streams/*_test.go`, `gateway/api_oas_servers_test.go`. |
| Auth/session/policy/rate | `gateway/mw_auth_key_test.go`, `gateway/mw_jwt_test.go`, `gateway/mw_basic_auth_test.go`, `gateway/mw_rate_limiting_test.go`, `gateway/session_manager_test.go`, `gateway/policy_test.go`, `user/*_test.go`, `internal/policy/*_test.go`, `internal/rate/**/*_test.go`, `tests/policy`, `tests/rate`, `tests/quota`. |
| Config/startup/reload | `config/*_test.go`, `gateway/server_test.go`, `gateway/reload_loop_test.go`, `gateway/api_config_test.go`, `gateway/dashboard_register_test.go`, `tests/lifecycle`, `tests/system`. |
| Storage/RPC/certificates | `storage/*_test.go`, `storage/kv/*_test.go`, `rpc/*_test.go`, `gateway/rpc*_test.go`, `gateway/redis_signals_test.go`, `certs/*_test.go`, `gateway/cert*_test.go`, `gateway/mw_certificate_check*_test.go`, `gateway/reverse_proxy_upstream_cert_test.go`, `internal/certcheck/*_test.go`, `internal/httpclient/*_test.go`. |
| Plugins/coprocess | `coprocess/*_test.go`, `coprocess/grpc/*_test.go`, `coprocess/python/*_test.go`, `goplugin/*_test.go`, `gateway/*plugin*_test.go`, `gateway/coprocess_bundle_test.go`, `tests/coprocess/bundle_loading_test.go`, `ci/tests/plugin-compiler`. |
| Observability/protocols | `internal/event/event_test.go`, `gateway/event_handler_webhooks*_test.go`, `gateway/event_system_test.go`, `internal/otel/*_test.go`, `internal/otel/apimetrics/*_test.go`, `trace/*_test.go`, `gateway/tracing_test.go`, `internal/graphql/*_test.go`, `gateway/mw_graphql*_test.go`, `internal/mcp/*_test.go`, `gateway/mw_mcp*_test.go`, `gateway/mw_jsonrpc*_test.go`, `ci/tests/metrics`, `ci/tests/tracing`. |

INT requirements are candidates only when direct integration evidence exists:

| Boundary | Candidate INT claim | Evidence gate |
| --- | --- | --- |
| API definition -> gateway loader -> router | Loaded Classic/OAS/MCP definitions produce intended live routes and middleware chains. | Black-box gateway request tests that load definitions and issue HTTP requests. |
| Gateway auth middleware -> session store -> policy service | Request auth resolves session, applies policy, and enforces access/quota/rate without stale state. | Gateway middleware tests spanning storage and `internal/policy`; Redis-backed cases only when Redis is provisioned by the proof runner. |
| Gateway `RPCStorageHandler` -> RPC client/control plane | Key, policy, API, cert, and node-state sync handles retry, emergency mode, DNS reconnect, and cache invalidation. | `gateway/rpc*_test.go` plus `rpc/*_test.go`; mocked RPC is enough for local boundary behavior, not live MDCB behavior. |
| Gateway certificate middleware -> certificate manager/storage | API mTLS and upstream TLS select and validate scoped certificates. | Live gateway TLS tests, certificate manager tests, and storage pull-through tests. |
| Gateway middleware -> coprocess/gRPC/Python dispatcher | Gateway serializes request/session/event objects and applies returned mutations or overrides. | Gateway coprocess tests with actual dispatcher path and explicit build tags. Generated protobuf tests alone are not enough. |
| Gateway -> OTel/Prometheus/tracing exporters | Gateway emits configured metrics/traces with stable names, labels, resource attrs, and span hierarchy. | CI metrics/tracing scenarios or exporter-visible tests, not only provider setup unit tests. |
| JSON-RPC/MCP middleware -> protocol router/access control | JSON-RPC bodies route to VEMs/MCP primitives and session rights deny/pass correctly. | Gateway middleware tests plus router unit tests; router-only tests stay SW. |

## Evidence Hazards

These surfaces are likely to create fake green checks if treated casually:

- `gateway/testutil.go`, fixtures, generated mocks, and helper packages enable
  evidence but are not evidence by themselves.
- Build-tagged tests (`ee || dev`, `jq`, `unstable`, `!race`, old Go tags,
  `coprocess`, `python`, `grpc`, `goplugin`) only count when the proof command
  actually runs them.
- Mocked dashboard/RPC/storage paths are useful SYS evidence for gateway
  fallback behavior but weak INT evidence for live control-plane or Redis
  behavior.
- Redis, Consul, Vault, OTel collector, tracing, and plugin compiler scenarios
  need provisioned dependencies before claims can be made at SYS/INT level.
- `storage.MdcbStorage` and dummy storage contain partial implementations;
  do not claim every `storage.Handler` method is safe for every implementation.
- TLS bypass knobs such as `SSLInsecureSkipVerify` must be modeled as explicit
  configured behavior, never as a secure default.
- `internal/event` context tests, `apidef` schema tests, and `internal/mcp`
  router tests prove helper behavior; they do not prove webhook delivery,
  runtime API routing, or gateway access control without gateway-level tests.
- `user` model/lemma annotations are useful SW invariants, not proof that a
  request was authorized or denied correctly.

## Onboarding Waves

Each wave must add scope only after the requirement/evidence shape is ready.
The expected loop is: define capability-level STK/SYS, add SW decomposition for
implementation packages, annotate only proven code and tests, run package tests,
run stage checks, and rerun strict audit.

Recommended waves:

| Wave | Scope | Reason | Primary risk |
| --- | --- | --- | --- |
| 0 | Build-surface repair and exclusion audit: `internal/build`, generated mocks, test-only packages, build-tagged packages | A repo-honest gate cannot rely on `go build ./...` while imported production packages are deleted or while generated/test-only code is mixed into production completeness. | Do not hide broken build surfaces by excluding them without rationale. Restore or explicitly classify before expanding CLI/plugin scope. |
| 1 | Rate/quota runtime: `internal/rate`, `internal/rate/model`, selected `gateway/session_manager.go`, `gateway/mw_rate_limiting.go`, and `tests/rate`/`tests/quota` evidence | Rate/quota behavior is product-facing, already tied to gateway session limiting, and has focused tests for headers, key formatting, smoothing, allowance, storage, and sliding-log behavior. | Redis-dependent paths and `internal/rate/limiter` need careful evidence review; do not annotate untested limiter algorithms or Redis-backed behavior unless dependencies run. |
| 2 | API definition lifecycle: `apidef`, `apidef/oas`, `apidef/adapter`, `apidef/importer`, `apidef/mcp`, selected `gateway/api_*` tests | API definitions are the gateway product surface that turns operator intent into routes, middleware, security, and protocol behavior. | Schema/model unit tests are SW evidence; SYS claims need runtime loader/router evidence. |
| 3 | Gateway request-routing slice: focused `gateway` loader/mux/proxy/middleware families with black-box request tests | `gateway` is the largest surface and must be sliced by product behavior rather than onboarded as one component. | `gateway` has many helper fixtures, build tags, and mocked dependencies. Keep annotations scoped to behavior asserted by each test. |
| 4 | MCP/JSON-RPC cluster: `internal/mcp`, `internal/jsonrpc`, `internal/jsonrpc/errors`, selected gateway MCP/JSON-RPC tests | Product-facing and relatively bounded by protocol request/response behavior. | Avoid standalone requirements for registry constants or prefix helpers. Router-only tests stay SW. |
| 5 | GraphQL cluster: `internal/graphengine`, `internal/graphql`, selected gateway GraphQL tests | Product-facing request execution, access control, persisted operations, and telemetry behavior with existing tests. | External engine coupling and generated mocks make over-annotation likely. |
| 6 | Certificate/TLS cluster: `certs`, `internal/certcheck`, `internal/httpclient`, selected gateway certificate tests | Security-critical and user-visible. | Generated mocks, async cooldown/event behavior, and TLS bypass knobs need explicit modeling. |
| 7 | Storage/RPC/control-plane: `storage`, `storage/kv`, `rpc`, selected gateway RPC/storage tests | Worker/control-plane consistency and persistence are core Tyk reliability behavior. | Partial storage implementations contain panics; avoid broad interface claims and distinguish mocked RPC from live MDCB. |
| 8 | Observability: `internal/otel`, `internal/otel/apimetrics`, `trace`, `internal/service/newrelic`, event/webhook tests | Operators consume stable event, metric, span, and trace fields. | Provider setup tests do not prove exporter-visible output. |
| 9 | Plugins/coprocess/CLI: `coprocess`, `goplugin`, `dlpython`, `cli/*`, gateway plugin/bundle tests | Extensibility and operator tooling are product-facing but have build-tag and external-toolchain hazards. | Requires Wave 0 build repair and explicit build-tag/test-command decisions before evidence is honest. |

Obvious INT candidates remain deliberately deferred until direct integration
evidence exists: live gateway request flow, Redis-backed state, MDCB/RPC sync,
certificate/TLS lifecycle, plugin execution, external services, protocol
coverage, and CLI output consumed by a live gateway.

### Wave 0 Build-Surface Gate

Wave 0 is a hard prerequisite for repo-wide strictness. The deleted
`internal/build/version.go` is production surface, not documentation churn:

- `goplugin/plugin_name_builder.go` imports `internal/build` and uses
  `build.Version` for plugin filename/version matching.
- `cli/cli.go` imports `internal/build` and exposes `app.Version`.
- `cli/version/version.go` imports `internal/build` and prints `Version`,
  `BuiltBy`, `BuildDate`, and `Commit`.
- `gateway/version.go` imports `internal/build` for deprecated compatibility
  version variables.
- `ci/goreleaser/goreleaser.yml` injects those variables with release-time
  `-X` flags.

Clean options:

1. Restore `internal/build/version.go` as the production build-info package, or
   replace it consistently across all consumers and release metadata.
2. Do not exclude `cli`, `goplugin`, or `gateway/version.go` merely to make
   repo-wide build pass; that would hide a real production build break.
3. Treat environment-dependent tests as provisioned integration gates. Current
   repo-wide tests also need Redis for rate/RPC/storage cases and a valid
   `PYTHON_VERSION` for `dlpython`; these are prerequisites, not warnings to
   suppress.

### Wave 1 Rate/Quota Entry Plan

The rate/quota wave must not start by claiming the whole rate limiter product
surface. The safe first entry is a bounded SW slice plus selected gateway SYS
evidence:

| Candidate | Layer | Honest claim | Evidence gate | Do not claim yet |
| --- | --- | --- | --- | --- |
| Header sender | SW under rate/quota response headers | `internal/rate` selects quota-vs-rate header sender, serializes rate stats, clamps negative remaining to zero, and clears quota headers in the rate-limit sender path. | `internal/rate/headers_test.go`; later gateway tests for 429/403 header semantics. | Full middleware lifecycle, quota-blocked response behavior, or upstream header interaction from unit tests alone. |
| Key formatting | SW under rate state | `Prefix` trims separators, skips empty fragments, and joins remaining fragments with single dashes; `LimiterKey` chooses session hash unless custom keys are requested. | `internal/rate/rate_test.go`, additional focused tests for `LimiterKey` before annotation. | Correctness of every gateway key scope or endpoint suffix. |
| Redis client/TLS config | SW under rate storage configuration | `NewStorage` chooses failover/cluster/simple Redis client shape and `createTLSConfig` applies best-effort legacy or external-services mTLS settings. | `internal/rate/storage_test.go`, `internal/rate/storage_tls_test.go`. | Successful secure Redis connection, fail-closed security, or external-service availability. |
| Smoothing arithmetic | SW under rate smoothing | Increase/decrease helper functions adjust by step and clamp to max/threshold according to trigger comparisons. | `internal/rate/smoothing_test.go`, plus added boundary tests for equality and no-change clamp cases before MC/DC gating. | Locking, reread-after-lock, event emission, or gateway smoothing precedence unless separately tested. |
| Smoothing orchestration | SW/SYS depending on scope | `Smoothing.Do` rejects invalid config, creates first allowance, rate-limits updates by delay, locks before updates, and emits up/down events on changed allowance. | Existing tests are partial; add focused mock-store tests for get/lock/set errors, expired false before/after lock, increase/decrease events, and no-change path. | Gateway-visible smoothing behavior until `SessionLimiter.limitRedis` tests cover it. |
| Sliding-log Redis script | SW under Redis rate storage | `SetCountScript` returns pre-add count, remaining, limit, and reset duration from Redis script output; `Do` fails closed on script/storage error. | Redis-provisioned `internal/rate/sliding_log_test.go` plus explicit script error/remaining/reset branch tests. | Distributed multi-node correctness, Redis cluster/failover topology, or product rate-limit admission behavior. |
| Limiter adapters | SW adapter only | Wrappers construct external `exp/pkg/limiters` algorithms with Redis or local storage. | Add local adapter tests if these enter scope. | Algorithm correctness for leaky/token/sliding/fixed window; release reachability for adapters not selected by current config. |
| Gateway rate/quota behavior | SYS | Configured rates reject excess requests with 429; quotas reject exhausted quota with 403; effective limits come from session/API/endpoint scope. | `gateway/mw_rate_limiting_test.go`, `gateway/session_manager_test.go`, `tests/rate/*` when dependencies are provisioned. | Claims from `internal/rate` unit tests alone; skipped tests do not count. |

Do not add `./internal/rate` or `./internal/rate/limiter` as whole-package
proof scope until their gates are ready. `go test ./internal/rate
./internal/rate/limiter -count=1` is currently not a dependency-free proof
gate: `internal/rate` has Redis-backed sliding-log tests, and
`internal/rate/limiter` has no test files. A dependency-free first slice may
use focused tests for `Prefix`, header sender behavior, TLS config mapping,
allowance-store mock behavior, and smoothing arithmetic, but not Redis
sliding-log correctness, external limiter algorithm correctness, or gateway
429/403 behavior.

Wave 1 likely bug or disposition surfaces to investigate before green claims:

- Sliding-log sorted-set member uses `now.UnixNano()` as the member, so
  same-nanosecond requests may collide and undercount.
- Sliding-log script appears to add blocked requests, which may intentionally
  enforce cooldown but needs a product decision before it becomes a SYS claim.
- Invalid TLS files log and continue; that is best-effort configuration, not
  fail-closed security.
- Some comments describe reset as a duration while rate-limit headers serialize
  `X-RateLimit-Reset` as a Unix timestamp.
- Limiter wrappers truncate `float64` rates to `int64`, do not validate
  zero/negative/fractional rate or period inputs, and leaky bucket sleeps
  without context cancellation.
- Several useful quota/rate tests are skipped; they cannot be used as evidence
  until unskipped or replaced.

## Migration Rules

1. Preserve existing policy-engine proof behavior while refactoring the graph.
   The PR currently claims policy-engine formal verification and 0/0 audit; do
   not weaken those guarantees.
2. Re-anchor package-level stakeholder requirements before adding more
   packages. Requirements such as "the internal UUID package shall..." are SW
   candidates, not durable STK stories.
3. Keep SYS requirements black-box. A SYS requirement may say "API definition
   loading rejects path traversal"; the SW child may say `internal/sanitize`
   uses bounded URL decoding and component validation.
4. Use INT requirements only for real boundaries, for example gateway policy
   loading into `internal/policy.Service`, dashboard policy fetch into gateway
   policy store, bundle extraction into filesystem writes, or gateway analytics
   emission into pump-facing records. Each INT requirement needs direct
   `:integration:integration` evidence.
5. Domain facts are not requirements. Permission matrices, mutually exclusive
   policy modes, enumerated states, and bounds belong in vars files as ranges,
   mutex groups, decision tables, or data constraints.
6. Known product bugs stay as KnownIssues with reproducer evidence. Do not
   weaken requirements to match broken software.

## Migration Checkpoints

- 2026-06-19: Removed the unfinished `internal/maps` proof slice from
  `proof.yaml`, requirements, variables, traces, evidence comments, and docs.
  The package is intentionally out of scope until a real gateway story needs
  it.
- 2026-06-19: Reframed `STK-REQ-008` through `STK-REQ-015` from private
  package ownership wording into gateway-level product concerns:
  policy/API inventory, observability metadata, identifiers, configuration
  timing, compressed payloads, input containment, node network identity, and
  policy-file access. Their existing SYS children remain as the current
  verified carriers until a deliberate SW decomposition is introduced.
- 2026-06-19: `proof validate --format json` passed with `126/126` artifacts
  valid and `0` warnings/errors. `proof workflow check --stage spec --verbose
  --format json` passed with `0` warnings/errors.
- 2026-06-19: Restored `proof_complexity_clean` budgets to the tight passing
  values `75` formalized requirements, `85` variables, and `70` guarantees.
  The oversized increase to `145` variables was not needed; the live check
  passes at `85`, while lowering formalized requirements to `70` correctly
  flags the policy slice at `75`.
- 2026-06-19: Began the real three-level migration with the identifier slice:
  `SYS-REQ-083` is now gateway identifier behavior (`component:
  identifiers`), while `SW-REQ-001` owns the `internal/uuid` package behavior
  that satisfies it. Implementation annotations moved to `SW-REQ-001`; tests
  still witness the system and stakeholder behavior they exercise.
- 2026-06-19: Removed three unbacked same-package `reqproof:assume`
  directives around policy endpoint helper calls after confirming with a
  no-cache verification run that all 10 components still pass solver
  realization, consistency, vacuity, and gap analysis. This avoids retaining
  over-strong helper contracts while the requirements hierarchy is being
  tightened.
- 2026-06-19: Added `SW-REQ-002` as the first policy software decomposition
  under `SYS-REQ-008`. It owns the concrete `internal/policy.Service.Apply`
  success/error result behavior, with row evidence on idle setup, successful
  Apply, and nil-store rejection. Helper constructors are not treated as Apply
  evidence.
- 2026-06-19: Migrated the readable-duration slice from package-shaped system
  modeling to a three-level shape: `SYS-REQ-084` now owns gateway
  configuration timing preservation (`component: configuration_timing`), while
  `SW-REQ-003` owns the concrete `internal/time.ReadableDuration` helper
  behavior and source annotations.
- 2026-06-19: Migrated the event metadata slice from package-shaped system
  modeling to a three-level shape: `SYS-REQ-082` now owns gateway
  observability metadata preservation (`component: observability`), while
  `SW-REQ-004` owns the concrete `internal/event` helper behavior and source
  annotations. The false MC/DC row was moved from unknown-event string fallback
  to request-encoding failure evidence, where the test actually proves the
  negative path.
- 2026-06-19: Migrated the node network identity slice from package-shaped
  system modeling to a three-level shape: `SYS-REQ-095` through `SYS-REQ-097`
  now own gateway node address discovery outcomes (`component:
  node_network_identity`), while `SW-REQ-005` owns the concrete
  `internal/netutil.GetIpAddress` helper behavior and source annotations.
  Loopback-only discovery is modeled as an allowed empty-success case, not as
  a false witness for available-address reporting.
- 2026-06-19: Logged `KI-RATE-QUOTA-HEADER-INT-NARROWING` with a current
  static reproducer evidence manifest instead of fixing production code or
  promoting an unverified rate-header requirement slice. The active defect is
  visible, while the full rate/quota header requirement hierarchy remains
  deferred to the rate/quota onboarding wave where gateway acceptance and MC/DC
  evidence can be added honestly.

## Current Covered Components And Destination Layer

| Current component | Current modeling smell | Target layer |
| --- | --- | --- |
| `internal/policy` | Mostly SYS-level behavior for policy application, but some helper and method-specific claims are implementation detail. | Keep gateway-visible policy outcomes as SYS; migrate Apply/ClearSession/helper invariants to SW under those SYS contracts. |
| `internal/model` | Currently framed as a stakeholder story about an internal package. | SW under policy loading, API inventory, RPC/storage, and gateway reporting SYS stories. |
| `internal/event` | Migrated: `SW-REQ-004` owns helper behavior under `SYS-REQ-082` observability metadata preservation. | Keep as SW; add INT only if an emitted event producer/consumer boundary is modeled with direct integration evidence. |
| `internal/uuid` | Private identifier helper package. | SW under API definition/import, OAuth/client identity, host checker, and generated-record ID stories. |
| `internal/time` | Private duration helper package. | SW under configuration parsing/runtime timeout SYS stories. |
| `internal/compression` | Helper package used by backup/RPC/server flows. | SW under compressed payload integrity/resource-bound SYS stories; possible INT if wire/storage compressed payload contract is modeled. |
| `internal/sanitize` | Security helper currently modeled as package story. | SW under bundle extraction, API ID/path component, and policy/API file safety SYS stories. |
| `internal/netutil` | Migrated: `SW-REQ-005` owns helper behavior under `SYS-REQ-095` through `SYS-REQ-097` node network identity outcomes. | Keep as SW under gateway node identity/startup diagnostics SYS stories. |
| `internal/osutil` | Scoped filesystem helper currently modeled as package story. | SW under policy file access and bundle/file operation SYS stories. |
| `internal/rate` | Not yet covered. Product-facing rate/quota behavior with helper subpackages. | SYS under auth/session/rate limiting and persistence stories; SW for key formatting, header sender, smoothing, allowance, storage, and algorithm helpers. |

## First Migration Slice

The first slice should be the branch's original scope: policy application.

Recommended shape:

- STK: API platform administrators and security engineers need policy changes
  to produce correct authorization, rate, quota, endpoint, and error behavior.
- SYS: gateway policy application behavior, including successful merge,
  failed-apply atomicity, clear/reapply behavior, performance bound, and
  concurrent request safety.
- SW: `internal/policy.Service` methods, `internal/model` store adapters, and
  comparison/merge helpers that implement the SYS policy contracts.
- INT: only after a direct gateway-to-policy integration test exists for the
  boundary between gateway session handling and `internal/policy.Service`.

After that slice is clean, migrate helper packages only when their consuming
gateway SYS story is identified.
