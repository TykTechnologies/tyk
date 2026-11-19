---
name: mcp-oauth-diagnostics
description: Diagnose Tyk Gateway MCP OAuth discovery and client interoperability failures, including mirror and broker mode and localhost versus HTTPS ingress. Use for incident investigation and minimal reproductions; do not substitute this workflow for implementing fixes, security reviews, running a test suite, or CI triage.
license: MPL-2.0
---

# Diagnose Gateway MCP OAuth

Identify the first failing protocol step using the checked-out implementation and the [discovery reference](references/discovery.md). The reference owns Gateway code pointers, mode semantics, and regression-test entry points; recheck them against the deployed revision.

Record Gateway, client, and SDK versions; supported MCP authorization revision; selected mode and relevant API configuration; public URL, internal listener, upstream authority, and TLS termination. Mark missing facts as unknown. Compare working and failing deployments without treating localhost success as HTTPS deployment evidence.

Trace the unauthenticated MCP response through `WWW-Authenticate`, Protected Resource Metadata, authorization-server metadata, and the client's next attempted step. Distinguish TLS, discovery, registration, authorization, token exchange, and the authenticated MCP operation. Check resource, issuer, endpoint, and path expectations for the selected mode. Preserve legitimate upstream identities where the implementation retains them.

Remain read-only. Use supplied artifacts, source, and unauthenticated discovery responses from endpoints identified by the task. Verify advertised destinations against the expected authorities before following them. Registration, interactive login, token exchange, and MCP operations require task authorization for those actions. Keep independent mirror and broker failures separate until evidence connects them.

Do not invent configuration overrides, disable certificate verification, weaken credential transport checks, or copy credentials or customer captures into reusable instructions. Report redacted expected-versus-observed evidence, confirmed facts versus hypotheses, a minimal reproduction, what actually ran, remaining gaps, and the next discriminating check. Hand confirmed defects or missing regressions to the requested implementation or test workflow without silently starting it.
