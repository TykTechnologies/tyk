# RFC: REST APIs as MCP via a Three-Layer Proxy → Adapter → REST Architecture

**RFC Number:** TT-API-TO-MCP-V9
**Author(s):** Andrei Puscuta (with architecture co-design via Claude)
**Date:** 2026-05-12
**Status:** Draft

---

## 1. Introduction

### 1.1. Background

Tyk Gateway today manages REST APIs and (as of commit `4e3b745c7`, "Support remote MCPs as upstream") can also reverse-proxy a remote MCP server while applying gateway policies to agent-side traffic. The remote case rides on the existing `IsMCP()` flag (`apidef/api_definitions.go:1452`), the `JSONRPCMiddleware` chain insertion (`gateway/mw_jsonrpc.go:61`), and the `/tyk/mcps` CRUD surface (`gateway/server.go:916-920`).

What is **not** supported today: turning a Tyk-managed REST API into an MCP-callable surface so that AI agents (Claude Desktop, Cursor, VSCode plugins, etc.) can invoke its operations as MCP tools. Operators want this without standing up a translator service, and — critically — they want every existing piece of Tyk middleware on the REST side (auth, rate-limit, validation, transforms, plugins, post-plugins) to run on every agent invocation. The PoC currently in tree (`gateway/mcp_proxy_catalogue.go`, `apidef/oas/mcp_proxy_derive.go`, plus `docs/mcp-proxy-poc.md`) explores one shape but references types that do not exist in the codebase (`oas.MCPProxy`, `MCPCallerAuth`) and bakes in cross-resource back-references that complicate hot reload and multi-tenant safety.

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
      curation: expose-all          # or strict-opt-in (with a tools: map)
```
The REST API is **not** marked `IsMCP()`. It still serves REST traffic on its existing listenPath under its existing chain. The `mcp` block is a marker that tells the loader to synthesise a paired adapter.

**Layer B — MCP Adapter (synthetic, in-memory, Internal).** When `loadApps` sees `mcp.enabled: true` on a loaded REST APISpec, it constructs and registers a paired APISpec entirely in memory:
- Deterministic API ID: `<rest-apiid>__mcp-adapter`.
- `Internal: true` (skipped by the public muxer per `gateway/api_loader.go:196`).
- Chain: `JSONRPCMiddleware` (existing) followed by a new `MCPAdapterMiddleware` that handles `initialize`, `ping`, `tools/list`, and `tools/call` inline (no per-tool VEMs).
- Holds `Middleware.McpTools` populated by `oas.DeriveSourceTools` (`apidef/oas/mcp_proxy_derive.go:42`) from the REST API's OAS, filtered by curation.
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
    url: tyk://id:7da15d555e0346975780a6bc28a37d67__mcp-adapter
```
The `mcpCreateHandler` admit path calls `MarkAsMCP()` (`apidef/api_definitions.go:1457`), so `IsMCP()` returns true and `JSONRPCMiddleware` is wired into the chain via the existing gate at `gateway/mw_jsonrpc.go:61`. The proxy holds **all** agent-side concerns: authentication scheme, rate limits, quotas, observability tags. Its upstream is the synthetic adapter via `tyk://id:<X>__mcp-adapter`.

**Request flow for `tools/call`:**

1. Agent → `POST /mcp/orders/` with JSON-RPC envelope and Tyk key. Proxy chain runs unchanged: auth middleware authenticates, rate-limit/quota middleware enforce agent-side limits, session lands in request context.
2. Proxy reverse-proxies the JSON-RPC envelope to `tyk://id:<X>__mcp-adapter`. The loop primitive at `gateway/api_loader.go:715` dispatches into the adapter's chain.
3. Adapter's `JSONRPCMiddleware` parses the envelope; `MCPAdapterMiddleware` resolves the tool by name from `Middleware.McpTools`, expands `arguments` into path / query / header / body per the tool's `ParamLocations`, builds an HTTP request matching the source operation, sets a new context flag `httpctx.SetMCPLoopFromPairedProxy(req, callerProxyAPIID)`, and loops to `tyk://id:<rest-apiid>`.
4. REST chain runs. A new tiny middleware `MCPLoopAuthBypass` is inserted at the top of the auth band (`gateway/api_loader.go:367-528`). It reads the trust flag; if present and `gw.mcpPairing[restAPIID] == callerProxyAPIID`, it marks the request as session-pre-authorised and skips credential validation. If the flag is present but pairing does not match, it returns 403 (defence-in-depth forgery catch). If the flag is absent, normal auth runs (REST clients are unaffected).
5. Rate-limit, quota, validation, transforms, plugins, post-plugins, upstream all run normally with the proxy's session in context. Rate limits stack: agent-facing at the proxy, server-facing on the REST chain (lower of the two effectively governs; see §2.3 for the session-shape nuance).
6. Upstream HTTP response unwinds back through REST → adapter. Adapter wraps it as `{ result: { content: [{ type: "text", text: <body> }], isError: <status> >= 400 }}` and returns. Proxy reverse-proxy returns the JSON-RPC envelope to the agent.

**Request flow for `tools/list`, `initialize`, `ping`:** Adapter answers inline from its in-memory state; no loop hop, no upstream call.

### 2.2. Benefits

- **One operator change unlocks MCP exposure.** Toggle `mcp.enabled: true` on the REST API + deploy a one-page proxy APIDef. No third object to manage, no new admin endpoint, no new RBAC subject.
- **Zero divergence between REST and MCP behaviour.** Every existing middleware on the REST API runs on every agent `tools/call` because the call physically traverses the REST chain via the loop primitive. Operators do not maintain two policy attachments.
- **No persisted tool snapshot.** The catalogue is derived at every load via `oas.DeriveSourceTools` (already pure and gateway-agnostic). REST OAS edits propagate on the next reload with no MCP-side re-save.
- **Narrow trust channel.** `MCPLoopAuthBypass` is the **only** place that observes the trust flag; existing auth middlewares (`AuthKey`, `JWT`, `Oauth2KeyExists`, etc.) are not modified. Multi-tenant safety is enforced twice — at admit (OrgID match) and at runtime (pairing-index check).
- **Reuses existing primitives.** `IsMCP()` flag, `/tyk/mcps` CRUD, `JSONRPCMiddleware`, the `tyk://` loop primitive, `Internal` APISpec flag, `DeriveSourceTools` — all already in tree. No new resource kind in `syncResourcesWithReload` (`gateway/server.go:1391`), no new storage shape across the three backends.
- **Clean separation of concerns.** Proxy owns agent-edge (auth, rate-limit). Adapter owns MCP protocol translation. REST API owns business logic. Each layer is independently understandable and testable.

### 2.3. Potential Risks/Challenges

- **Synthetic APISpec is a new pattern.** Tyk has no precedent for APISpecs that exist only in `gw.apisByID` without a corresponding storage entry. Reload semantics, replication paths (RPC backend), and any tooling that enumerates loaded APIs must be audited for "synthetic-aware" handling. **Mitigation:** synthesis happens late in `loadApps` after storage-driven specs are loaded; the synthetic spec is keyed by a deterministic suffix that backend code can recognise as derived. The synthetic spec is rebuilt on every reload from the source REST APISpec, so no drift is possible.
- **Pairing-index staleness.** `gw.mcpPairing` and `gw.mcpAdapter` must be rebuilt atomically with `loadApps`. If a proxy is deleted mid-reload, a stale entry could authorise an orphan adapter. **Mitigation:** rebuild the index by full scan after specs are loaded; never mutate it incrementally outside reload. The index is read-only between reloads.
- **Session-shape coupling between proxy and REST API.** Tyk rate limits are session-keyed; a session minted by the proxy carries `access_rights[proxyAPIID]` but not necessarily `access_rights[restAPIID]`. Three sub-cases (documented in §4.3): (a) policy grants both → both per-API limits stack; (b) policy grants only the proxy → REST falls back to its global limit if set, otherwise no REST-side limit; (c) operator wants only the proxy to govern → leave the REST global limit unset and grant only the proxy. Surprising for operators new to MCP. **Mitigation:** documentation; example policies for both single-tier and stacked configurations.
- **`tools/call` returning a 4xx/5xx from the REST chain becomes an MCP `isError: true` envelope.** Surprising if the proxy's rate limit is loose and the REST API's rate limit is tight — agent gets MCP-shaped 429s instead of HTTP-shaped ones. **Mitigation:** documentation guides operators to set proxy limits ≤ REST limits in normal cases; the JSON-RPC error code field (`error.code`) carries the original HTTP status for clients that want to disambiguate.
- **Streaming or large REST responses.** MCP's single-shot `result.content` envelope cannot represent chunked HTTP responses well. **Mitigation:** v1 buffers; payloads above a configured threshold get a `_meta.truncated: true` tag. Streaming MCP responses (server-sent events) are a v2 concern.
- **`fuzzyFindAPI` host disambiguation.** `tyk://<host>` resolution at `gateway/api_loader.go:723-739` matches on name *or* APIID. To address the synthetic adapter unambiguously we adopt the convention `tyk://id:<X>__mcp-adapter` and add an exact-match branch that fires when the host has the `id:` prefix, falling back to fuzzy matching otherwise. **Mitigation:** trivial code change, exhaustive test for collision cases.

### 2.4. Alternatives Considered

- **In-tree PoC shape (separate `MCPProxy` aggregator APIDef with `sources[]` back-refs).** Rejected because (a) the `oas.MCPProxy` and `MCPCallerAuth` symbols referenced by the PoC do not exist in the codebase — confirmed by repo-wide grep — so the PoC would not compile cleanly, and (b) cross-resource back-refs from source APIs to aggregators are load-bearing and complicate hot reload, multi-tenant validation, and "delete the source" semantics.
- **One operator-facing APIDef that does both edge concerns and MCP translation (no separate proxy + adapter).** Simpler operator UX (one object instead of two) but conflates agent-edge auth with MCP protocol translation, makes future aggregation impossible without a breaking change, and forces the MCP translator to live inside an APIDef that is also a public listener. Rejected for separation of concerns.
- **Adapter as a Tyk middleware bolted onto the REST API itself (second listenPath on the same APIDef).** Two listenPaths per APIDef is not supported by the muxer today; adding it would change the loader's invariants. The split-into-three-objects approach uses existing primitives (`Internal` flag, loop) rather than introducing a new one.
- **Adapter as an explicit operator-managed APIDef** rather than synthetic. Easier on the loader (no new pattern) but worse UX (operator manages an object they do not conceptually care about) and creates drift risk if the operator edits the adapter inconsistently with the REST API. Rejected for operator UX.
- **Dashboard-side spawning of the adapter** (admin layer writes a sibling APIDef to storage when `mcp.enabled` is toggled). Avoids the synthetic-APISpec novelty but creates a real cleanup-on-delete problem and pushes runtime concerns into the admin layer. Rejected for tighter coupling between Dashboard and gateway lifecycle.
- **Sidecar `tyk-mcp` binary.** Cleanest isolation but no sidecar pattern exists in Tyk today and the policy-attachment requirement means the sidecar would have to call back into the gateway anyway, doubling the network hops. Rejected as disproportionate.
- **Blanket `SetSelfLooping` trust on the REST chain.** Existing flag, zero new context plumbing — but creates a wide trust channel that every auth middleware must respect, and any future feature that triggers a self-loop would inherit it. The narrower `SetMCPLoopFromPairedProxy` flag plus the runtime pairing-index check keeps the trust decision in one middleware. Rejected for blast radius.
- **Slug-prefixed tool names (`orders__getOrder`)** instead of bare operationIds. Future-proofs an aggregation feature that v1 explicitly defers. Bare operationIds are cleaner in agent UIs and v1's 1:1 proxy-to-adapter model has no collision risk. If aggregation lands, it can introduce its own naming rule without breaking 1:1 setups. Rejected as premature.

---

## 3. Technical Details

### 3.1. Implementation

**File-level changes** (line numbers verified against current HEAD on `master`, 2026-05-12):

| File | Change |
|---|---|
| `apidef/oas/server.go` | Add `MCP *MCP` field on `Server`. New `apidef/oas/mcp.go` peer holding `MCP { Enabled, Curation, Tools }` with Fill/ExtractTo round-trip and JSON-schema entry. |
| `apidef/oas/mcp_proxy_derive.go:42` | Keep `DeriveSourceTools` unchanged. It is the load-time engine; pure and gateway-agnostic. |
| `apidef/oas/mcp_primitive.go` | No change. Existing `MCPPrimitives` map of `*MCPPrimitive` is reused for the adapter's `Middleware.McpTools`. |
| `gateway/api_definition.go:1789` (`extractMCPPrimitivesToPaths`) | When the spec is the synthetic adapter, call `DeriveSourceTools` against the source REST OAS and populate `Middleware.McpTools` in memory before `ExtractPrimitivesToExtendedPaths` runs. |
| `gateway/api_definition.go:1835` (`initMCPConfiguration`) | Construct `JSONRPCRouter` for the adapter as today; existing call site at line 1841 already does this for `IsMCP()` specs. |
| `gateway/api_definition.go:2497` (`populateMCPPrimitivesMap`) | No change. Already keys off `Middleware.McpTools`; runs naturally for the synthetic adapter. |
| `gateway/api_loader.go` (new function `synthesiseMCPAdapter`) | After the public-spec load loop in `loadApps`, walk loaded REST specs whose OAS sets `mcp.enabled: true` and synthesise the paired adapter spec. Register it in `gw.apisByID` and `gw.apisHandlesByID` with `Internal: true`. ID format: `<rest-apiid>__mcp-adapter`. |
| `gateway/api_loader.go:715` (loop primitive) | No change. Add only an exact-match branch in `findInternalHttpHandlerByNameOrID` (`:791`) that fires when host has `id:` prefix to avoid `fuzzyFindAPI` name-collision risk. |
| `gateway/api_loader.go:367-528` (auth band) | Insert a new tiny middleware `MCPLoopAuthBypass` at the top of the band. ~30 LOC; only active on REST APIs marked `mcp.enabled: true`. |
| `gateway/mw_mcp_loop_auth_bypass.go` (new file) | New middleware. Reads `httpctx.GetMCPLoopFromPairedProxy(req)`; if absent → next. If present, look up `gw.mcpPairing[thisRESTAPIID]`; if it equals `callerProxyAPIID` → mark session-pre-authorised, return next. If mismatch → 403. |
| `gateway/mw_jsonrpc.go:61` (`EnabledForSpec`) | No change to the gate. Inside `ProcessRequest` (line 161) inline-handle `initialize`, `ping`, `tools/list` for adapter specs (synthetic responses); leave `tools/call` to dispatch through `MCPAdapterMiddleware`. |
| `gateway/mw_mcp_adapter.go` (new file) | New middleware. For `tools/call`: resolve tool by name from `spec.Middleware.McpTools`, expand arguments per `ParamLocations`, build HTTP request, set `httpctx.SetMCPLoopFromPairedProxy(newReq, callerProxyAPIID, restAPIID)`, set `newReq.URL = tyk://id:<rest-apiid>`, dispatch via existing loop. Wrap response as MCP `result` envelope. |
| `gateway/mcp_proxy_catalogue.go` (current PoC, 125 lines) | **Delete.** References non-existent `oas.MCPProxy` symbol. Its responsibility is replaced by `synthesiseMCPAdapter`. |
| `gateway/mcp_api.go:43` (`validateMCP`) | Extend admit-time validation: when proxy `upstream.url` is `tyk://id:<X>__mcp-adapter`, verify (a) REST APISpec `<X>` exists in the org, (b) it has `mcp.enabled: true`, (c) no other proxy in the org targets the same adapter (1:1 invariant), (d) OrgID match. |
| `gateway/server.go:916-920` (`/tyk/mcps` routes) | No change. Existing CRUD handles the proxy. |
| `gateway/server.go:1385-1393` (`syncResourcesWithReload`) | No change. The marker on the REST API and the `IsMCP()` flag on the proxy do not introduce new resource kinds. |
| `gateway/gateway.go` (Gateway struct) | Add `mcpPairing map[string]string` (restAPIID → proxyAPIID) and `mcpAdapter map[string]string` (restAPIID → adapterAPIID). Rebuilt in full on every `loadApps` after specs are loaded. |
| `internal/httpctx` | Add `SetMCPLoopFromPairedProxy(req, proxyAPIID, restAPIID)` and `GetMCPLoopFromPairedProxy(req)`. Single context-key, single getter, single setter. |
| `internal/mcp/router.go` | No change. Adapter's inline handling sits in `MCPAdapterMiddleware`, not the router. |
| `internal/mcp/list_filter.go:75` | No change. Existing per-session `tools/list` filter applies if the proxy's policy carries MCP access controls. |
| `gateway/res_handler_mcp_list_filter.go:15` | The synthesis fast-path for `tools/list` on the adapter must write through this response handler before returning, or per-session tool curation breaks. Verified via e2e test. |
| `gateway/mcp_synthesis.go` | No change. Existing per-method/per-primitive rate limits from access rights keep working. |
| `gateway/mcp_oauth_proxy.go` | No change. PRM/AS proxy logic is remote-MCP-only and orthogonal. |

**Files that do not need to exist:** sidecar binary, new go.mod module, new RPC payload kind, new admin endpoints, new resource kind, `MCPProxy` struct, `MCPCallerAuth` middleware, back-references on the REST APIDef, `acceptMcpLoopCallers` consent flag.

### 3.2. Dependencies

- **No new external dependencies.** All required primitives are in tree: `IsMCP()`, `MarkAsMCP()`, `JSONRPCMiddleware`, the `tyk://` loop primitive, `Internal` flag, `DeriveSourceTools`, `MCPPrimitive`, `MCPPrimitives` map, `apisByID`/`apisHandlesByID` registries, `/tyk/mcps` CRUD, `validateMCP` admit hook.
- **No new infrastructure.** No sidecar, no out-of-process translator, no new storage, no new replication path.
- **Compile-time prerequisite:** delete the broken `gateway/mcp_proxy_catalogue.go` PoC (references non-existent `oas.MCPProxy`). It currently sits in the working tree as untracked; before merging this RFC's implementation it must be removed or its build excluded.
- **Runtime prerequisite:** the existing remote-MCP feature (commit `4e3b745c7`) remains untouched; this RFC is additive.

### 3.3. Migration Plan

- **No data migration.** Operators with no MCP usage are entirely unaffected.
- **Operators using the in-tree PoC (`MCPProxy.sources[]` shape):** the PoC was never released; the broken file is untracked. Migrate by (a) marking each source REST API with `mcp.enabled: true`, (b) creating one MCP proxy APIDef per source (was previously one MCPProxy with N sources). The 1:1 model means each ex-source becomes its own `/mcp/<name>/` listenPath. Aggregation (one proxy, many sources) is explicitly deferred.
- **Operators using the merged remote-MCP feature:** unaffected. Their existing `IsMCP()` proxies pointing at remote MCP URLs continue to work; this RFC only adds the REST-as-MCP path.
- **Rollback:** removing `mcp.enabled: true` from the REST API on the next reload removes the synthetic adapter. Removing the proxy APIDef via `/tyk/mcps` removes the agent-facing surface. Both are non-destructive.

---

## 4. Impact

### 4.1. Teams/Departments Affected

- **Gateway engineering:** owns implementation, ~11 engineer-days (see §4.2).
- **Dashboard team:** minor — a JSON-schema update for the `mcp:` block on REST OAS so the form renders the new field; UI work for the dashboard view of `/tyk/mcps` already exists for the remote-MCP feature.
- **Documentation:** new operator guide for "Expose a REST API as MCP" replacing `docs/mcp-proxy-poc.md`. Three rate-limit sub-cases must be documented clearly.
- **Solutions / SE:** customer demo updates; the existing `apps/*mcp*.json` PoC files become outdated.
- **Security:** review of the `MCPLoopAuthBypass` middleware, the pairing-index trust model, and the multi-tenant admit-time check in `validateMCP`.

### 4.2. Financial Impact

**11 engineer-days, single engineer, including tests.** Assumptions: engineer is familiar with `apidef/oas` round-trip patterns and Tyk's middleware loader; CI for OAS round-trip and JSON-RPC e2e tests already exists; no Dashboard work is in scope (a one-line schema entry against `apidef/oas/schema/x-tyk-api-gateway.json` is included).

Breakdown:
- 2d — `MCP` struct in `apidef/oas/server.go` peer + Fill/ExtractTo + JSON-schema entry + round-trip tests.
- 2d — `synthesiseMCPAdapter` in `gateway/api_loader.go`; pairing-index construction in `loadApps`; exact-match `id:` branch in loopback resolver.
- 1d — `MCPAdapterMiddleware` (`gateway/mw_mcp_adapter.go`) — tools/call translation, argument expansion, response wrapping.
- 1d — `JSONRPCMiddleware.ProcessRequest` inline `initialize` / `ping` / `tools/list` short-circuit for adapter specs.
- 1d — `MCPLoopAuthBypass` middleware (`gateway/mw_mcp_loop_auth_bypass.go`); chain insertion; `httpctx` setter/getter.
- 1d — `validateMCP` admit-time checks (existence, mcp.enabled, 1:1, OrgID); delete the broken `gateway/mcp_proxy_catalogue.go` PoC.
- 2d — End-to-end tests: agent-key → proxy → adapter → REST chain → upstream; multi-tenant rejection; reload picks up REST OAS edits without re-saving the proxy; pairing-index forgery attempt returns 403; rate-limit sub-cases (a)/(b)/(c).
- 1d — Hot-reload regression sweep: delete REST then list adapters; flip `mcp.enabled` off then on; delete proxy then re-create.
- 1d — Operator documentation rewrite (`docs/mcp-proxy-poc.md` → `docs/mcp-rest-as-mcp.md`).

**No infrastructure cost.** No new processes, no new storage, no new external dependencies.

### 4.3. Training/Documentation Needs

- New operator guide: "Expose a Tyk-managed REST API as MCP." Includes the two-file YAML walkthrough, the `tyk://id:<X>__mcp-adapter` convention, agent-client configuration examples (Claude Desktop, Cursor).
- Rate-limit guide: explicit documentation of the three sub-cases (proxy-only, REST-global fallback, stacked) with example session policies for each.
- Security guide: explanation of the paired-proxy trust model, what `MCPLoopAuthBypass` does, what the pairing-index check protects against.
- Existing PoC documentation (`docs/mcp-proxy-poc.md`) is **deprecated** and should be replaced wholesale.
- Internal SE training: 30-minute walkthrough for solutions engineers covering operator UX, rate-limit nuance, and demo flow.

---

## 5. Feedback

Feedback should be left as comments on this RFC document or in the corresponding ticket. Specific points where reviewer input is requested:

- **Synthetic APISpec novelty.** Is the loader-emits-synthetic-spec pattern acceptable, or do we want the adapter to be storage-backed despite the cost?
- **Bare operationId tool naming.** Confirm v1's 1:1 model means we do not need slug-prefixing yet.
- **Defence-in-depth pairing-index check at runtime.** Belt-and-braces against trust-flag forgery, or unnecessary given that the flag is set inside the gateway process by trusted code?
- **Two stacked rate limits.** Is the lower-of-two-effectively-governs behaviour the right default, or should the proxy's limit always be authoritative (REST-side rate-limit middleware skipped on adapter loop hops)?

---

## 6. Decision

### 6.1. Outcome

Pending review. Recommended outcome: **Approved**.

### 6.2. Reasoning

The design satisfies all six hard constraints from the original brief without introducing a new resource kind, a new storage shape, a new admin endpoint, or a wide trust channel. It reuses every relevant primitive already in tree (`IsMCP()`, `/tyk/mcps`, `JSONRPCMiddleware`, the `tyk://` loop, `Internal`, `DeriveSourceTools`) and isolates the only novel piece (synthetic APISpec emission) to one new function in `gateway/api_loader.go`. Cost is bounded at 11 engineer-days. The trust model has two independent enforcement points (admit-time OrgID + 1:1 check; runtime pairing-index check). Aggregation, OAuth 2.1 PKCE, streaming MCP responses, resources/prompts primitives, and dashboard UI work beyond JSON-edit are explicitly deferred.

### 6.3. Next Steps

1. Land RFC for review; collect feedback (one week).
2. On approval, write implementation plan via `superpowers:writing-plans`.
3. Implementation in order: (a) `apidef/oas` MCP struct + round-trip tests, (b) `synthesiseMCPAdapter` + pairing index, (c) `MCPAdapterMiddleware` + `MCPLoopAuthBypass`, (d) `validateMCP` extension + delete broken PoC, (e) e2e test suite, (f) docs.
4. Internal demo to SE / product before merging to `master`.
5. Beta opt-in for one design-partner customer; iterate on rate-limit and curation UX based on feedback.
6. Plan v2 enhancements (in priority order): aggregation (one proxy, many adapters), OAuth 2.1 PKCE on the agent side, streaming responses, resources/prompts derivation, Dashboard UI for MCP toggle.
