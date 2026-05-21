# RFC: REST APIs as MCP via a Three-Layer Proxy → Adapter → REST Architecture

**RFC Number:** TT-API-TO-MCP-V9
**Author(s):** Andrei Puscuta
**Date:** 2026-05-13
**Status:** Implemented (TT-17123) — branch `TT-17123-poc-api-to-mcp-v2`

---

## 1. Introduction

### 1.1. Background

Tyk Gateway today manages REST APIs and (as of commit `4e3b745c7`, "Support remote MCPs as upstream") can also reverse-proxy a remote MCP server while applying gateway policies to agent-side traffic. The remote case rides on the existing `IsMCP()` flag (`apidef/api_definitions.go`), the `JSONRPCMiddleware` chain insertion (`gateway/mw_jsonrpc.go`), and the `/tyk/mcps` CRUD surface (`gateway/server.go`).

What was **not** supported: turning a Tyk-managed REST API into an MCP-callable surface so that AI agents (Claude Desktop, Cursor, VSCode plugins, etc.) can invoke its operations as MCP tools. Operators want this without standing up a translator service, and — critically — they want every existing piece of Tyk middleware on the REST side (auth, rate-limit, validation, transforms, plugins, post-plugins) to run on every agent invocation.

### 1.2. Purpose

Define the **REST-as-MCP** capability: a way for an operator to mark an existing Tyk-managed REST API as agent-callable via MCP, such that:

- Agents talk to a normal Tyk listenPath that authenticates them with a Tyk key and applies agent-side rate limits.
- Every `tools/call` ultimately runs through the REST API's full middleware chain so that policy attachment is preserved.
- The operator manages two objects (the REST API itself, plus an MCP proxy APIDef) — both via existing CRUD endpoints. No third hand-managed object, no new resource kind, no new storage shape, no new context flag with wide blast radius.
- Multi-tenant safety is enforced at admit time and again at runtime (defence in depth) without requiring every auth middleware to learn a new trust signal.
- The tool catalogue is derived from the REST API's OAS at every reload (no persisted snapshot, no admin-time re-save dance).

Remote-MCP wrapping is **out of scope**: it is already supported via `IsMCP()` and the JSON-RPC middleware path.

---

## 2. Proposed Change

### 2.1. Description

Three runtime objects, two operator-managed, one synthetic.

**Layer C — REST API (operator-managed, pre-existing).** Operator adds one block to the OAS:
```yaml
x-tyk-api-gateway:
  server:
    mcp:
      enabled: true
      # expose: [getOrder, createOrder]  # optional allow-list; omit for expose-all
```
The `mcp` block is a marker that tells the loader to synthesise a paired adapter. The classic-APIDefinition projection is `apidef.MCPExposureConfig` (`mcp_exposure.enabled`, `mcp_exposure.expose`). Default behaviour is to expose every operation in the source OAS; populate `expose` with the sanitised operationIds to whitelist. Operations marked `middleware.operations[<id>].internal.enabled: true` are unconditionally skipped — the operator's "internal-only" declaration outranks `expose`. The REST API is **not** marked `IsMCP()`. It still serves REST traffic on its existing listenPath under its existing chain.

**Layer B — MCP Adapter (synthetic, in-memory, Internal).** When `loadApps` sees `mcp.enabled: true` on a loaded REST APISpec, `synthesiseMCPAdapters` (`gateway/mcp_synthesise_adapter.go`) constructs and registers a paired APISpec entirely in memory:
- Deterministic APIID: `<rest-apiid>__mcp-server` (constant `oas.AdapterAPIIDSuffix`).
- `Internal: true` (skipped by the public muxer).
- Listen path stem `/__tyk-mcp-server/<rest-apiid>/` — only present to satisfy loader validation; the adapter is never reachable from the public muxer.
- `MarkAsMCP()` so `JSONRPCMiddleware` is wired into the chain.
- `UseKeylessAccess: true` (the adapter never sees an end-user credential; trust comes from the paired proxy via the loop primitive).
- Cloned `OAS` so `DerivedTools` can be produced from the source REST OAS via `oas.DeriveSourceTools` filtered by the optional `expose` allow-list. Tools are rebuilt on every reload — no persisted snapshot.
- `APISpec.IsSyntheticMCPAdapter = true` and `APISpec.SourceRESTAPIID = <rest-apiid>` for unambiguous identification.
- Lives in `gw.apisByID` and `gw.apisHandlesByID`. Not in storage. Not visible via `/tyk/apis` or `/tyk/mcps`.

**Layer A — MCP Proxy (operator-managed, explicit, 1:1 with one adapter).** A normal OAS APIDef the operator POSTs to `/tyk/mcps`:
```yaml
x-tyk-api-gateway:
  info: { name: orders-mcp-proxy, state: { active: true }}
  server:
    listenPath: { value: /mcp/orders/, strip: true }
    authentication:
      enabled: true
      securitySchemes: { authToken: { type: apiKey, in: header, name: Authorization }}
  middleware:
    global:
      rate_limit: { rate: 10, per: 1 }
  upstream:
    url: tyk://7da15d555e0346975780a6bc28a37d67__mcp-server
```
The admit-time handler in `gateway/mcp_api.go` recognises a paired-adapter upstream via `APIDefinition.IsPairedMCPAdapterProxy()` (matches `tyk://*__mcp-server` URLs) and **skips** `MarkAsMCP()` for it: the proxy stays a plain reverse-proxy, and the adapter alone owns JSON-RPC semantics. The proxy holds **all** agent-side concerns: authentication scheme, rate limits, quotas, observability tags.

**Request flow for `tools/call`:**

1. Agent → `POST /mcp/orders/` with JSON-RPC envelope and Tyk key. Proxy chain runs unchanged: auth middleware authenticates, rate-limit/quota middleware enforce agent-side limits, session lands in request context.
2. Proxy reverse-proxies the JSON-RPC envelope to `tyk://<X>__mcp-server`. The loop primitive dispatches into the adapter's chain.
3. Adapter's `JSONRPCMiddleware` parses the envelope. For `initialize`, `ping`, and `tools/list` the middleware short-circuits inline via `handleAdapterInline` (`gateway/mw_mcp_adapter.go`) using helpers from `internal/mcp/adapter`. For `tools/call` it hands off to `Gateway.handleAdapterToolsCall`, which:
   - resolves the tool by name from `spec.DerivedTools`,
   - calls `mcpadapter.BuildUpstreamRequest` to expand `arguments` into path / query / header / body per the tool's `ParamLocations`,
   - stamps `httpctx.SetMCPLoopFromPairedProxy(req, &MCPLoopTrust{ProxyAPIID, RESTAPIID, AdapterAPIID})`,
   - looks up the REST handler via `gw.findInternalHttpHandlerByNameOrID(spec.SourceRESTAPIID)` and invokes it directly with an `mcpadapter.Recorder` that captures status / headers / body.
4. REST chain runs. `MCPLoopAuthBypass` (`gateway/mw_mcp_loop_auth_bypass.go`) sits at the top of the auth band and reads the trust descriptor. If present and `gw.mcpPairing.ProxyForREST(restAPIID) == trust.ProxyAPIID`, it installs a stub session marking the request session-pre-authorised and the normal auth middlewares short-circuit. If the descriptor is present but the pairing index disagrees, it returns 403 (defence-in-depth forgery catch). If the flag is absent, normal auth runs (REST clients are unaffected).
5. Rate-limit, quota, validation, transforms, plugins, post-plugins, upstream all run normally with the loop session in context. Rate limits stack: agent-facing at the proxy, server-facing on the REST chain.
6. The adapter wraps the recorder output via `mcpadapter.ToolResultEnvelope` into `{ result: { content: [{ type: "text", text: <body> }], isError: <status>>=400, _meta: {...} }}` and writes the JSON-RPC envelope. The proxy returns it verbatim to the agent.

**Request flow for `tools/list`, `initialize`, `ping`:** adapter answers inline from its in-memory state; no loop hop, no upstream call.

### 2.2. Benefits

- **One operator change unlocks MCP exposure.** Toggle `mcp.enabled: true` on the REST API + deploy a one-page proxy APIDef. No third object to manage, no new admin endpoint, no new RBAC subject.
- **Zero divergence between REST and MCP behaviour.** Every existing middleware on the REST API runs on every agent `tools/call` because the call physically traverses the REST chain. Operators do not maintain two policy attachments.
- **No persisted tool snapshot.** The catalogue is derived at every load via `oas.DeriveSourceTools` (pure and gateway-agnostic). REST OAS edits propagate on the next reload with no MCP-side re-save.
- **Narrow trust channel.** `MCPLoopAuthBypass` is the **only** place that observes the trust descriptor; existing auth middlewares (`AuthKey`, `JWT`, `Oauth2KeyExists`, etc.) are not modified. Multi-tenant safety is enforced twice — at admit (OrgID match + 1:1 check in `validateMCP`) and at runtime (`pairing.Index.ProxyForREST` cross-check).
- **Reuses existing primitives.** `IsMCP()` flag, `/tyk/mcps` CRUD, `JSONRPCMiddleware`, the `tyk://` loop primitive, `Internal` APISpec flag, `DeriveSourceTools` — all already in tree. No new resource kind in `syncResourcesWithReload`, no new storage shape across the three backends.
- **Clean separation of concerns.** Proxy owns agent-edge (auth, rate-limit). Adapter owns MCP protocol translation. REST API owns business logic. Each layer is independently understandable and testable; the protocol pieces live in `internal/mcp/adapter` and the pairing state in `internal/mcp/pairing`, both gateway-free packages.

### 2.3. Potential Risks/Challenges

- **Synthetic APISpec is a new pattern.** Tyk has no prior precedent for APISpecs that exist only in `gw.apisByID` without a corresponding storage entry. Reload semantics, replication paths (RPC backend), and any tooling that enumerates loaded APIs must be audited for "synthetic-aware" handling. **Mitigation:** synthesis happens late in `loadApps` after storage-driven specs are loaded; the synthetic spec is keyed by a deterministic suffix and the `APISpec.IsSyntheticMCPAdapter` flag so backend code can recognise it. The synthetic spec is rebuilt on every reload from the source REST APISpec, so no drift is possible.
- **Pairing-index staleness.** `gw.mcpPairing` (a `*pairing.Index`) must be rebuilt atomically with `loadApps`. If a proxy is deleted mid-reload, a stale entry could authorise an orphan adapter. **Mitigation:** `rebuildMCPPairing` computes a fresh `(pairing, adapter)` map pair by full scan of the in-flight spec register and swaps them under the `Index`'s internal lock; the index is read-only between reloads.
- **Session-shape coupling between proxy and REST API.** Tyk rate limits are session-keyed. Three sub-cases (documented in operator guide): (a) policy grants both APIs → both per-API limits stack; (b) policy grants only the proxy → REST falls back to its global limit if set; (c) operator wants only the proxy to govern → leave the REST global limit unset and grant only the proxy.
- **`tools/call` returning a 4xx/5xx from the REST chain becomes an MCP `isError: true` envelope.** Surprising if the proxy's rate limit is loose and the REST API's rate limit is tight — agent gets MCP-shaped 429s instead of HTTP-shaped ones. **Mitigation:** documentation guides operators to set proxy limits ≤ REST limits in normal cases.
- **Streaming or large REST responses.** MCP's single-shot `result.content` envelope cannot represent chunked HTTP responses. **Mitigation:** v1 buffers; `mcpadapter.Recorder` caps captured body at `BodyTruncationBytes` (1 MiB) and the envelope's `_meta.truncated` reflects overflow. Streaming MCP responses (SSE) are a v2 concern.
- **`fuzzyFindAPI` host disambiguation.** `tyk://<host>` resolution matches on name *or* APIID. The adapter APIID's deterministic `__mcp-server` suffix ensures exact-APIID matching wins before any fuzzy name-based match could collide.

### 2.4. Alternatives Considered

- **In-tree PoC shape (separate `MCPProxy` aggregator APIDef with `sources[]` back-refs).** Rejected because (a) the referenced symbols (`oas.MCPProxy`, `MCPCallerAuth`) did not exist in the codebase, and (b) cross-resource back-refs from source APIs to aggregators are load-bearing and complicate hot reload, multi-tenant validation, and "delete the source" semantics.
- **One operator-facing APIDef that does both edge concerns and MCP translation (no separate proxy + adapter).** Simpler UX but conflates agent-edge auth with MCP protocol translation, makes future aggregation impossible without a breaking change, and forces the MCP translator to live inside an APIDef that is also a public listener. Rejected for separation of concerns.
- **Adapter as a Tyk middleware bolted onto the REST API itself (second listenPath on the same APIDef).** Two listenPaths per APIDef is not supported by the muxer today; adding it would change the loader's invariants.
- **Adapter as an explicit operator-managed APIDef** rather than synthetic. Easier on the loader (no new pattern) but worse UX (operator manages an object they do not conceptually care about) and creates drift risk if the operator edits the adapter inconsistently with the REST API.
- **Dashboard-side spawning of the adapter** (admin layer writes a sibling APIDef to storage when `mcp.enabled` is toggled). Avoids the synthetic-APISpec novelty but creates a real cleanup-on-delete problem and pushes runtime concerns into the admin layer.
- **Sidecar `tyk-mcp` binary.** Cleanest isolation but no sidecar pattern exists in Tyk today and the policy-attachment requirement means the sidecar would have to call back into the gateway anyway, doubling the network hops.
- **Blanket `SetSelfLooping` trust on the REST chain.** Existing flag, zero new context plumbing — but creates a wide trust channel that every auth middleware must respect. The narrower `MCPLoopTrust` descriptor plus the runtime pairing-index check keeps the trust decision in one middleware.
- **Slug-prefixed tool names (`orders__getOrder`)** instead of bare operationIds. v1's 1:1 model has no collision risk; if aggregation lands it can introduce its own naming rule.

---

## 3. Technical Details

### 3.1. Implementation

The implementation is on branch `TT-17123-poc-api-to-mcp-v2`. Files that materially changed or were added:

| File | Purpose |
|---|---|
| `apidef/oas/mcp.go` | OAS `MCP` struct (`Enabled`, `Expose []string`) under `server.mcp`, with Fill/ExtractTo round-trip and linter coverage. Empty `Expose` means "expose all operations". |
| `apidef/oas/server.go` | `MCP *MCP` field added to `Server`. |
| `apidef/oas/schema/x-tyk-api-gateway.json`, `.strict.json` | New `X-Tyk-MCP` definition and `server.mcp` reference (strict variant also sets `additionalProperties: false`). |
| `apidef/oas/mcp_proxy_derive.go` | `DeriveSourceTools` (REST OAS → `[]DerivedTool` with `ParamLocations`). Hosts `AdapterAPIIDSuffix = "__mcp-server"`, `AdapterAPIID`, `IsAdapterAPIID`, `AdapterSourceAPIID`, `AdapterLoopHost`, `AdapterLoopURL`. |
| `apidef/oas/mcp_exposure_test.go` | Round-trip and suffix-helper tests. |
| `apidef/api_definitions.go` | `MCPExposureConfig` struct, `MCPExposure` field on `APIDefinition`, `IsMCPExposed()`, `IsPairedMCPAdapterProxy()`, `IsMCPManaged()` helpers. |
| `apidef/schema.json` | Adds `mcp_exposure` to the classic-APIDefinition JSON schema (the Dashboard validates classic payloads against this; without the entry, `additionalProperties:false` rejects the field). |
| `gateway/model_apispec.go` | Adds `IsSyntheticMCPAdapter`, `SourceRESTAPIID`, `DerivedTools` fields to `APISpec`. |
| `gateway/mcp_synthesise_adapter.go` | `synthesiseMCPAdapters` (build & register adapter specs in-memory), `buildAdapterSpec` (clone REST spec, mark Internal + MarkAsMCP + keyless, populate `DerivedTools`), `rebuildMCPPairing` / `computeMCPPairing` (rebuild `gw.mcpPairing` on every reload). Adapter listen path stem `/__tyk-mcp-server/`. |
| `gateway/mw_mcp_adapter.go` | `JSONRPCMiddleware.handleAdapterInline` (inline `initialize` / `ping` / `tools/list`) and `Gateway.handleAdapterToolsCall` (build upstream request, stamp trust descriptor, invoke REST handler with `Recorder`, wrap result envelope). |
| `gateway/mw_mcp_loop_auth_bypass.go` | `MCPLoopAuthBypass` middleware. `EnabledForSpec` is true only on `IsMCPExposed()` REST APIs. Reads `httpctx.GetMCPLoopFromPairedProxy(r)`; verifies it against `pairing.Lookup`; installs `makeMCPLoopSession` stub or returns 403 on forgery. |
| `gateway/mw_jsonrpc.go` | Short-circuits adapter `initialize` / `ping` / `tools/list` and routes adapter `tools/call` to `handleAdapterToolsCall` before normal JSON-RPC routing. |
| `gateway/api_loader.go` | Calls `synthesiseMCPAdapters` after storage-driven specs are loaded; inserts `MCPLoopAuthBypass` at the top of the auth band on `IsMCPExposed()` REST chains. |
| `gateway/mcp_api.go` | `validateMCP` extended: when admit-time payload upstream URL is `tyk://<X>__mcp-server`, verify (a) REST APISpec `<X>` exists in the org, (b) it has `mcp.enabled: true`, (c) no other proxy in the org targets the same adapter (1:1 invariant), (d) OrgID match. Skips `MarkAsMCP()` for paired-proxy admits (`IsPairedMCPAdapterProxy()`). |
| `gateway/api_helpers.go`, `gateway/util.go`, `gateway/server.go` | Pairing-index plumbing on the `Gateway` struct; small helpers for adapter identification used at admit and reload time. |
| `gateway/mcp_rest_as_mcp_test.go` | End-to-end test: agent → proxy → adapter → REST chain → upstream; multi-tenant rejection; reload picks up REST OAS edits without re-saving the proxy. |
| `ctx/ctx.go` | New context key `MCPLoopFromPairedProxy`. |
| `internal/httpctx/mcp_loop.go` | `MCPLoopTrust` descriptor (`ProxyAPIID`, `RESTAPIID`, `AdapterAPIID`), `SetMCPLoopFromPairedProxy`, `GetMCPLoopFromPairedProxy`. |
| `internal/mcp/adapter/adapter.go`, `adapter_test.go` | Gateway-free protocol package: `MethodInitialize` / `MethodPing` constants, `ProtocolVersion`, `JSONRPC*` codes, `InitializeResult`, `ToolsListResult`, `FindTool`, `BuildUpstreamRequest`, `Recorder` (with `BodyTruncationBytes = 1 MiB`), `ToolResultEnvelope`, `JSONRPCResult`, `JSONRPCError`, `WriteJSON`. |
| `internal/mcp/pairing/pairing.go`, `pairing_test.go` | `pairing.Index` (mutex-guarded) holding `restAPIID → proxyAPIID` and `restAPIID → adapterAPIID` maps. Exposes `New`, `Set`, `ProxyForREST`, `AdapterForREST`, `PairingSnapshot`. `Static` type and `Lookup` interface for unit-test injection (`MCPLoopAuthBypass.Pairing pairing.Lookup`). |
| `docs/mcp-rest-as-mcp.md`, `docs/mcp-rest-as-mcp.ipynb` | Operator guide and a runnable notebook walkthrough. |

**Files that intentionally do not exist:** sidecar binary, new go.mod module, new RPC payload kind, new admin endpoints, new resource kind, `MCPProxy` struct, `MCPCallerAuth` middleware, back-references on the REST APIDef, `acceptMcpLoopCallers` consent flag.

### 3.2. Dependencies

- **No new external dependencies.** All required primitives are in tree: `IsMCP()`, `MarkAsMCP()`, `JSONRPCMiddleware`, the `tyk://` loop primitive, `Internal` flag, `DeriveSourceTools`, `apisByID`/`apisHandlesByID` registries, `/tyk/mcps` CRUD, `validateMCP` admit hook.
- **No new infrastructure.** No sidecar, no out-of-process translator, no new storage, no new replication path.
- **Runtime prerequisite:** the existing remote-MCP feature (commit `4e3b745c7`) remains untouched; this RFC is additive.
- **Dashboard prerequisite:** the embedded `apidef.Schema` from this repo must be updated in tyk-analytics (it validates classic-APIDef payloads with `additionalProperties:false`) so `mcp_exposure` is not rejected at admit time.

### 3.3. Migration Plan

- **No data migration.** Operators with no MCP usage are entirely unaffected.
- **Operators using the merged remote-MCP feature:** unaffected. Their existing `IsMCP()` proxies pointing at remote MCP URLs continue to work; this RFC only adds the REST-as-MCP path.
- **Rollback:** removing `mcp.enabled: true` from the REST API on the next reload removes the synthetic adapter. Removing the proxy APIDef via `/tyk/mcps` removes the agent-facing surface. Both are non-destructive.

---

## 4. Impact

### 4.1. Teams/Departments Affected

- **Gateway engineering:** owns implementation (this branch).
- **Dashboard team:** consume the updated `apidef.Schema` so the `mcp_exposure` field on classic APIDefinitions and the `X-Tyk-MCP` block in OAS are accepted by Dashboard-side validation. UI work is out of scope for v1 (operators edit YAML / use the API directly).
- **Documentation:** new operator guide `docs/mcp-rest-as-mcp.md` (in tree). Three rate-limit sub-cases must be documented in product docs.
- **Solutions / SE:** customer demo updates; the notebook (`docs/mcp-rest-as-mcp.ipynb`) is intended to be the demo backbone.
- **Security:** review of `MCPLoopAuthBypass`, the `MCPLoopTrust` descriptor, the pairing-index trust model, and the multi-tenant admit-time check in `validateMCP`.

### 4.2. Financial Impact

**No infrastructure cost.** No new processes, no new storage, no new external dependencies.

### 4.3. Training/Documentation Needs

- Operator guide: "Expose a Tyk-managed REST API as MCP." Includes the two-file YAML walkthrough, the `tyk://<X>__mcp-server` convention, agent-client configuration examples.
- Rate-limit guide: explicit documentation of the three sub-cases (proxy-only, REST-global fallback, stacked) with example session policies for each.
- Security guide: explanation of the paired-proxy trust model, what `MCPLoopAuthBypass` does, and what the pairing-index check protects against.
- Internal SE training: 30-minute walkthrough for solutions engineers covering operator UX, rate-limit nuance, and demo flow.

---

## 5. Feedback

Specific points where reviewer input is requested:

- **Synthetic APISpec novelty.** Is the loader-emits-synthetic-spec pattern acceptable, or do we want the adapter to be storage-backed despite the cost?
- **Bare operationId tool naming.** Confirm v1's 1:1 model means we do not need slug-prefixing yet.
- **Defence-in-depth pairing-index check at runtime.** Belt-and-braces against trust-descriptor forgery, or unnecessary given that the descriptor is set inside the gateway process by trusted code?
- **Two stacked rate limits.** Is the lower-of-two-effectively-governs behaviour the right default, or should the proxy's limit always be authoritative (REST-side rate-limit middleware skipped on adapter loop hops)?

---

## 6. Decision

### 6.1. Outcome

Implemented on `TT-17123-poc-api-to-mcp-v2`. Pending review for merge to `master`.

### 6.2. Reasoning

The design satisfies all six hard constraints from the original brief without introducing a new resource kind, a new storage shape, a new admin endpoint, or a wide trust channel. It reuses every relevant primitive already in tree (`IsMCP()`, `/tyk/mcps`, `JSONRPCMiddleware`, the `tyk://` loop, `Internal`, `DeriveSourceTools`) and isolates the only novel piece (synthetic APISpec emission) to `gateway/mcp_synthesise_adapter.go`. The trust model has two independent enforcement points (admit-time OrgID + 1:1 check in `validateMCP`; runtime pairing-index check in `MCPLoopAuthBypass`). Aggregation, OAuth 2.1 PKCE, streaming MCP responses, resources/prompts primitives, and Dashboard UI work beyond schema acceptance are explicitly deferred.

### 6.3. Next Steps

1. ~~Land RFC for review.~~ Done.
2. ~~Implementation in order: (a) `apidef/oas` MCP struct + round-trip tests, (b) `synthesiseMCPAdapters` + pairing index, (c) `handleAdapterInline` + `handleAdapterToolsCall` + `MCPLoopAuthBypass`, (d) `validateMCP` extension, (e) e2e test suite, (f) docs.~~ Done on `TT-17123-poc-api-to-mcp-v2`.
3. Roll the updated `apidef.Schema` into tyk-analytics so Dashboard-side validation accepts `mcp_exposure` (CI is currently failing on this).
4. Internal demo to SE / product before merging to `master`.
5. Beta opt-in for one design-partner customer; iterate on rate-limit and exposure UX based on feedback.
6. Plan v2 enhancements (in priority order): aggregation (one proxy, many adapters), OAuth 2.1 PKCE on the agent side, streaming responses, resources/prompts derivation, Dashboard UI for MCP toggle.
