# TT-17123 REST-as-MCP RFC Comment Responses

This document captures suggested responses to the RFC review comments. The intent is to acknowledge valid concerns, separate v1 behavior from follow-up work, and avoid overpromising where the current implementation only provides the foundation.

## Response Stance

- The current v1 direction is still sound: derive MCP tools from REST OAS, expose them through a generated MCP proxy, and route execution back through the existing gateway path.
- The most important gaps to address before this is production-ready are operator visibility, tool catalogue enrichment, deterministic naming/collision behavior, truncation safety, and REST-as-MCP policy parity.
- Resources, progress notifications, richer streaming, and version-aware routing are valid follow-ups, but should be designed explicitly rather than folded into the first tool-only implementation.

## Laurentiu: Mark An Endpoint As A Resource

Comment:

> wondering (not sure) if we should be able to mark an endpoint as a resource. For instance an endpoint which has mock response and has lots of info (text) in it ? would such thing make sense?

Suggested answer:

> Yes, this makes sense, but I would keep it separate from the first tool-only version. MCP resources are application-driven context, while tools are model-invoked actions. A read-only endpoint with stable or text-heavy content could map well to `resources/list` and `resources/read`, especially for mock/static/documentation-style responses. I would capture this as a follow-up: add an endpoint-level MCP exposure mode such as `tool`, `resource`, or both.

Recommendation:

- Treat as a roadmap item.
- Add endpoint-level exposure mode when we introduce enrichment/config.
- Prefer resources for contextual data that the host/client chooses to include, not for actions the model invokes.

## Chris: Deleting REST API Leaves Dead MCP Proxy

Comment:

> Deleting the REST API leaves the MCP proxy in storage with a dead upstream. Is there a cleanup mechanism, or is that left to the operator?

Suggested answer:

> Good catch. For v1 we should not silently leave a broken proxy. The minimum behavior should be validation or pre-flight visibility showing the proxy is orphaned. Better behavior is cleanup or a disabled-state transition when the source REST API is deleted. I would propose either cascading delete for generated REST-as-MCP proxies, or marking them invalid with a clear dashboard/API warning if we want operator control.

Recommendation:

- Treat as a product behavior gap.
- Decide between cascade delete and invalid/disabled proxy state.
- Do not leave this as undocumented storage behavior.

## Chris: Missing `operationId` Visibility

Comment:

> Operations without an operationId - are they silently excluded from the tool catalogue, and does the operator have any pre-flight visibility into which operations will or won't become tools?

Suggested answer:

> Currently the derivation relies on `operationId`; operations without one should not become tools. We should make that visible: log skipped operations with method/path/reason, and expose the same information in the UI preview/pre-flight validation so operators know exactly what will and will not appear in the tool catalogue.

Recommendation:

- Add derivation warnings for skipped operations.
- Surface method, path, and skip reason.
- Show the final `tools/list` preview before enabling the MCP proxy.

## Laurentiu: Log And UI For Skipped Operations

Comment:

> I think at least at log level we should display that, and also some nice UI/UX stuff

Suggested answer:

> Agreed. Logging is the minimum. The better operator experience is a preview panel that shows included tools and skipped operations with reasons, because otherwise operators only discover missing tools from the MCP client side.

Recommendation:

- Add structured logs now.
- Track UI preview as part of the enrichment/config work.

## Laurentiu: Official MCP Go SDK, Tool Notifications, Lifecycle, Server Settings

Comment:

> let us use an official mcp go sdk here, we need to be able to notify when a tool is added/changed. are there any other notifications we need to handle? where do we store info like protocol version it implements, if it will have live list updates or not? I propose to have more settings under server.mcp

Suggested answer:

> Agreed. We moved the adapter onto the official MCP Go SDK path and now use a long-lived Streamable HTTP handler so sessions survive and `notifications/tools/list_changed` can be delivered. For now the only dynamic server notification we need is `tools/list_changed`, because the catalogue changes when the backing REST OAS changes. If and when we expose resources, we should add `resources/list_changed` too.
>
> I would not make protocol version operator-configurable unless there is a compatibility reason. The SDK/lifecycle should negotiate that. Product-level MCP settings under `server.mcp` make sense for Tyk behavior, for example enable/disable live catalogue updates, max response size, truncation behavior, exposure mode, and enrichment metadata.

Recommendation:

- Keep protocol lifecycle details owned by the SDK/adapter.
- Keep product behavior settings under `server.mcp`.
- Support `tools/list_changed` now.
- Add `resources/list_changed` only when resources are implemented.

## Laurentiu: Lifecycle Details

Comment:

> Here are more details on the spec Lifecycle - Model Context Protocol

Suggested answer:

> Yes, the gateway path should behave like a real Streamable HTTP MCP endpoint, not only a JSON-RPC POST shim. That means initialization, negotiated sessions, subsequent requests with the MCP session header, optional GET SSE streams, and DELETE session close should be routed to the SDK handler.

Recommendation:

- Keep POST, GET, and DELETE for synthetic MCP adapters routed directly to the SDK Streamable HTTP handler.
- Preserve gateway-level concerns around auth, rate limiting, and routing outside the SDK handler.
- Continue validating with real clients such as Roo/mcp-remote, not only unit tests.

## Laurentiu: Streaming Big Responses And Progress

Comment:

> can this stream the big responses from the API? update on progress of the upstream time if the request takes too long. MCP has this

Suggested answer:

> Streamable HTTP gives us the transport shape for server-to-client messages, GET SSE streams, and session lifecycle. That does not automatically mean REST upstream bodies are streamed through as MCP tool content. For v1 I would keep normal bounded tool responses, but we should add a follow-up for large/long-running calls: progress notifications when the client provides a `progressToken`, plus a better large-response strategy.

Recommendation:

- Do not claim full upstream body streaming in v1 unless implemented and tested end to end.
- Add progress notifications as a follow-up for long-running upstream calls.
- Pair this with the truncation fix so large responses are never silently presented as complete.

## Chris: Tool Catalogue Enrichment

Comment:

> There is no mechanism to override the tool catalogue derived from the REST OAS - tool names, descriptions, parameter descriptions, or behavioural hints - without modifying the source REST API, which operators may not own. Is a tool enrichment layer planned, and if so at which layer?

Suggested answer:

> Agreed. Raw OAS derivation is a good default, not the final authoring experience. We should add an enrichment layer outside the source OAS so operators can override tool name, title, description, parameter descriptions/examples, annotations, output schema, and visibility without changing the upstream REST API.

Recommendation:

- Treat enrichment as a required product layer, not a convenience.
- Put enrichment at the REST endpoint/operation mapping layer.
- Keep the source OAS unchanged.
- Generate the MCP catalogue from OAS plus enrichment overrides.

## Laurentiu: Per-Endpoint MCP Config And Preview

Comment:

> I would go with a per endpoint middleware like config, where we mark the endpoint mcp-able, and we can give it a new tool name, description and any metadata needed. Also would be good to present in this screen a json-rpc object on how MCP clients will see the tool

Suggested answer:

> I agree with the endpoint-level config direction. The UI should show both the derived tool and the final MCP shape after overrides, because operators need to understand what clients and models will actually see.

Recommendation:

- Add per-operation MCP config.
- Include visibility, exposure mode, tool name/title/description, parameter descriptions/examples, annotations, and output schema.
- Show the resulting `tools/list` JSON shape in UI/API preview.

## Chris: Flat Argument Name Collisions

Comment:

> DeriveSourceTools produces a flat arguments object - if an operation has a path param and a body field with the same name, which wins? Has a naming convention been considered?

Suggested answer:

> Good point. We should make collision handling deterministic. My preference is: preserve simple names when unambiguous, but when names collide, prefix by location: `path_id`, `query_id`, `header_id`, `body_id`. We should also emit a derivation warning so the operator sees why the final argument name changed.

Recommendation:

- Do not allow last-write-wins behavior.
- Preserve simple argument names where there is no collision.
- Prefix only collided names by location.
- Add warnings to logs and preview.

## Laurentiu: Internal `tyk://*__mcp-server`, Versioned APIs, And Public URL Shape

Comment:

> we need to check if the API is versioned and the id is a base API will that route to the right default version? what if version identifier is set to url param/header/query param, how do we handle that? I propose having smth like `tyk://<api-id>/mcp` to go with the standard here

Suggested answer:

> The `tyk://...__mcp-server` target should remain an internal implementation detail, not something operators author directly. We do need to explicitly define versioned REST API behavior. If the source API ID is a base API, the adapter should either route through the same gateway version resolution path as normal traffic or require a concrete version target. Header/query/path version identifiers need test coverage because they affect tool calls too.
>
> I would avoid exposing `tyk://<api-id>/mcp` as the storage contract unless we are ready to support it generally. A cleaner public abstraction is "create MCP proxy for REST API X"; the internal URL can change later.

Recommendation:

- Keep the synthetic adapter URL internal.
- Document and test versioned API behavior explicitly.
- Prefer public admin/API abstractions over requiring operators to author internal `tyk://` URLs.

## Chris: `MarkAsMCP` And Per-Tool Policy Controls

Comment:

> The proxy skips MarkAsMCP() because IsPairedMCPAdapterProxy() is true, making it a plain reverse-proxy. Does that mean per-consumer tool filtering, per-tool rate limiting, and per-tool allow/block lists are unavailable for REST-as-MCP in v1?

Suggested answer:

> This is a real v1 concern. Because the paired proxy behaves like a gateway route into the synthetic adapter, existing remote-MCP middleware semantics may not all apply automatically. We should either implement equivalent per-tool enforcement for REST-as-MCP or explicitly document the v1 limitation. I would prefer not shipping this as an implicit difference, because users will expect allow/block lists and per-tool controls to behave consistently across MCP proxy types.

Recommendation:

- Treat as a high-priority gap.
- Either run equivalent MCP tool policy enforcement for REST-as-MCP, or document the limitation explicitly.
- Avoid silent policy divergence between remote MCP proxies and REST-as-MCP proxies.

## Laurentiu: Same Gateway Instance And Tags

Comment:

> I am worried that the API and MCP Proxy need to sit on same GW instance. How can we ensure both share same tags, is the customer role to ensure that? is just a documentation piece?

Suggested answer:

> Yes, REST API and MCP proxy must be co-located on gateway instances that can resolve the internal adapter route. We should make this explicit. Ideally creation should copy or validate tag constraints so the proxy and REST API are deployed to the same gateway population. At minimum, the UI/API should warn when tags make the pairing unroutable.

Recommendation:

- Do not leave this as documentation only if we can validate it.
- Copy compatible tags or block/warn on incompatible tags at creation/update time.
- Add a runtime health/diagnostic signal for broken pairings.

## Chris: `_meta.truncated` Is Invisible To The Model

Comment:

> When a REST API returns a response larger than 1 MiB, the gateway cuts it off and sets `_meta.truncated: true`. The problem is that flag sits in metadata, but the LLM usually reads `content`. Is there a plan to put the truncation notice directly inside the content?

Suggested answer:

> Agreed. `_meta.truncated` alone is not enough because many clients do not pass metadata to the model. We should keep the machine-readable `_meta` flag, but also place a visible truncation notice in the returned `content`, before or after the truncated payload. For JSON responses, we should avoid returning broken JSON as if it were complete; either wrap the payload in an envelope or return a clear text/tool error explaining that the response exceeded the MCP limit.

Recommendation:

- Treat as a correctness/safety fix.
- Keep `_meta.truncated` for clients.
- Add visible content-level notice for models/users.
- Avoid returning invalid partial JSON as normal content.

## Chris: Bare `operationId` Tool Naming And Poor Parameter Names

Comment:

> operationId is designed for developer tooling. Many operationIds are invalid or poor tool names for LLMs. The same applies at the parameter level. There is currently no mechanism to address this without editing the source REST API OAS directly.

Suggested answer:

> The exact MCP name constraint has changed in the current spec: tool names are guidance-level `SHOULD`s, 1-128 characters, and dots are allowed. But the underlying concern is still correct: many `operationId`s are poor LLM tool names, and many parameter names lack enough semantic guidance. The right answer is enrichment plus validation: derive by default, warn on poor/invalid names, allow operator overrides, and show the final tool catalogue before enabling the proxy.

Recommendation:

- Validate generated names against current MCP guidance.
- Warn on names that are technically allowed but poor for model use.
- Add enrichment for names, titles, descriptions, examples, annotations, and output schemas.
- Keep raw OAS derivation as the default, not the only authoring path.

## Proposed Priority

### Should Address Before GA

- Visible truncation notice in `content`, not only `_meta`.
- Pre-flight preview and warnings for skipped operations, invalid/poor names, and collisions.
- Deterministic argument collision handling.
- Tool catalogue enrichment outside the source OAS.
- Policy parity or explicit limitation for per-tool controls.
- Cleanup/invalid-state behavior when source REST APIs are deleted.
- Tag/co-location validation for generated MCP proxies.

### Valid Follow-Ups

- REST endpoints exposed as MCP resources.
- `resources/list_changed` once resources exist.
- Progress notifications for long-running REST calls.
- Better large-response streaming/resource-link strategy.
- Versioned API routing policy and tests.
- Public abstraction for MCP proxy creation that hides internal `tyk://` target details.

## References

- MCP tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP Streamable HTTP transport: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP resources: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- MCP progress notifications: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress
