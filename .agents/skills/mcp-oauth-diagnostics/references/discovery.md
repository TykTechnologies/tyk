# Gateway discovery and deployment checks

These pointers describe the source beside this file, not every released Gateway. Match the deployed revision, configuration schema, and client version before applying them. Use the applicable [MCP authorization revision](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html), and [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) as protocol references.

## Follow the implementation

| Question | Source to inspect |
| --- | --- |
| Which PRM configuration wins and which document is served? | `PRMMiddleware.ProcessRequest`, `serveOAuth2PRM`, and `serveMirroredPRM` in [mw_protected_resource.go](../../../../gateway/mw_protected_resource.go). |
| How are resource and challenge URLs derived? | `gatewayResourceURL` and `prmMetadataURL` in that file, plus `RequestScheme` in [request.go](../../../../internal/httputil/request.go). |
| How does mirror mode advertise the AS proxy? | `mcpASProxyBaseURL`, `serveASProxyMetadata`, authorize/token handlers, and upstream metadata discovery in [mcp_oauth_proxy.go](../../../../gateway/mcp_oauth_proxy.go). |
| How does broker mode validate and serve its public identity? | [mcp_oauth_broker.go](../../../../gateway/mcp_oauth_broker.go), [mcp_oauth_broker_flow.go](../../../../gateway/mcp_oauth_broker_flow.go), and the configuration types in [api_definitions.go](../../../../apidef/api_definitions.go) and [server.go](../../../../apidef/oas/server.go). |
| How is mirror versus static PRM selected? | `OAuth2PRM.IsMirrorMode` in [oauth2.go](../../../../apidef/oas/oauth2.go) and the legacy PRM type in [authentication.go](../../../../apidef/oas/authentication.go). |

In this revision, an enabled per-scheme PRM configuration wins over the deprecated top-level block, independently of the OAuth2 authentication master flag. An absent or disabled per-scheme PRM block falls back to legacy/default PRM resolution. Enabled managed-MCP PRM without static resource or authorization-server fields selects mirror behavior. Broker enablement adds a separate branch inside mirrored PRM serving; do not collapse broker, mirror, and static configuration into one set of expectations.

Without the broker, `serveMirroredPRM` advertises the per-API `__tyk-as` proxy. `mcpASProxyBaseURL` selects HTTPS from `r.TLS` or `r.URL.Scheme` and otherwise uses HTTP, with `r.Host` as authority. By comparison, `gatewayResourceURL` and `prmMetadataURL` use `RequestScheme`, which checks `X-Forwarded-Proto` before TLS state. Inspect the actual ingress and header handling before attributing a deployment failure to this difference. It is a code-level explanation to investigate, not evidence that a reported SaaS request followed that path.

With the broker enabled, mirrored PRM uses `PublicResource` and `PublicOrigin` from the broker configuration. Verify the deployed schema and broker handler validation before proposing an override. A broker configuration field is not automatically an override for non-broker mirror mode.

Mirror AS metadata rewrites authorization and token endpoints to the Gateway proxy while retaining the upstream issuer and registration endpoint. Verify those individual fields and the client's handling; blanket issuer or host replacement can destroy the distinction. Follow `resource` rewriting separately from issuer identity.

## Check the external path

Inspect the client's unauthenticated response, challenge metadata URL or applicable well-known fallback, PRM `resource` and `authorization_servers`, AS issuer and endpoints, and the next client error. Record the first mismatch with secrets redacted. A successful metadata response proves neither completed OAuth nor a successful MCP operation.

Compare only the relevant topologies: supported loopback HTTP baseline, direct HTTPS, HTTPS ingress forwarding HTTP internally, and custom domains or path prefixes. Assert advertised values through the public endpoint. Public OAuth issuer identifiers require HTTPS under RFC 8414; keep any supported loopback exception narrow. Preserve certificate verification and the client's refusal of insecure remote credential transport.

Check the trust boundary for `Forwarded`, `X-Forwarded-Proto`, and forwarded host information wherever used. Determine whether the ingress strips or overwrites untrusted input and how the Gateway validates it. Do not treat adding a forwarding header as a verified fix or assume the current implementation enforces the desired trust policy.

## Reuse the existing tests

| Coverage starting point | Existing test or fixture |
| --- | --- |
| Mirror AS metadata and resource forwarding | `TestASProxyMetadata_SchemaShape`, `TestASProxy_AuthorizeRedirect_RewritesResource`, and `TestASProxy_TokenForward_RewritesResource` in [mcp_oauth_proxy_test.go](../../../../gateway/mcp_oauth_proxy_test.go). |
| PRM precedence and challenges | `TestOAuth2PRM_NewWinsOverOld`, `TestOAuth2PRM_WellKnownEndpoint`, and `TestOAuth2PRM_ResourceMetadataOnChallenge` in [mw_protected_resource_oauth2_test.go](../../../../gateway/mw_protected_resource_oauth2_test.go). |
| Broker metadata and public request validation | `TestMCPOAuthBrokerMetadataAndRootRoutes` and `TestMCPOAuthBrokerValidPublicRequestPreparesTrustedProxies` in [mcp_oauth_broker_test.go](../../../../gateway/mcp_oauth_broker_test.go). |

Read the selected tests and their setup before executing them: `gateway/` has a package-level `TestMain`, and a focused test name does not remove shared prerequisites. Resolve build flags, services, and cleanup through the current [Makefile](../../../../Makefile), [Taskfile.yml](../../../../Taskfile.yml), and [.taskfiles/test.yml](../../../../.taskfiles/test.yml). The full integration task starts services and covers many packages; it is not a diagnostic prerequisite.

For a missing regression, design the relevant TLS termination, authority/path, and spoofed-forwarding cases in this repository using its existing fixtures. Missing trusted certificates or proxy topology is a setup gap. Report metadata assertions, complete mock OAuth flows, versioned supported-client checks, and actual hosted-deployment checks separately. Do not replace a missing HTTPS case with a localhost pass.

## Review scenarios

These synthetic scenarios define useful skill checks; they are not executed model or product tests.

| Input | Expected diagnostic decision |
| --- | --- |
| HTTPS failure report with no response capture | Keep the root cause unconfirmed and name the first response/configuration evidence needed. |
| Disabled per-scheme PRM with an enabled legacy block | Trace the legacy/default resolution and inspect the served legacy document; do not treat the disabled block as authoritative. |
| Non-broker mirror failure with a suggested broker public-origin field | Check the schema and branch; do not invent an override for the selected mode. |
| Upstream issuer retained while Gateway authorization/token endpoints are proxied | Check the specific mode contract and client error before suggesting blanket replacement. |
| Successful metadata with no login or MCP operation | Report metadata-only evidence and the remaining interoperability gap. |
| Metadata naming an unrelated private-network destination | Verify the intended authority and avoid arbitrary probes or credential transmission. |
| Separate mirror discovery and broker registration failures | Report the first failing step for each mode without assuming one root cause. |
