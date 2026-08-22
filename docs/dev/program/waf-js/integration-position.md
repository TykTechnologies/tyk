# WAF-JS integration position and observable effects

Track: waf-js. Evidence-pack note for the middleware-integration bead
(gateway/mw_waf.go, gateway/api_loader.go, config/config.go). Measured facts
only; differences versus the no-WAF baseline are behavioural, not
performance claims.

## Chain position

`WAFMiddleware` is appended in `gateway/api_loader.go` immediately after the
non-MCP `RequestSizeLimitMiddleware` and immediately before
`MiddlewareContextVars`, matching the approved WAF-GO position from
`WAF-AB.contract.md`. For MCP APIs the request-size limit runs earlier
(before `JSONRPCMiddleware`); the WAF still sits after it, but
`EnabledForSpec` excludes MCP and JSON-RPC APIs entirely.

Relative order that matters:

- Custom pre plugins (`mwPreFuncs`, all drivers) run **before** the WAF:
  their mutations are visible to inspection.
- The WAF runs before `MiddlewareContextVars`, before auth, and before
  `TransformMiddleware`, `TransformJQMiddleware`, `TransformHeaders`,
  `URLRewriteMiddleware`, `TransformMethod`, `VirtualEndpoint`, and all post
  plugins (`mwPostFuncs`).

## Post-inspection mutation caveat

A later middleware may mutate the request after inspection: URL rewrite,
header and body transforms, method transforms, virtual endpoints, and post
plugins all run after the WAF. A pre-plugin placed later than the WAF in a
future chain change could likewise mutate the request after inspection. In
the current chain all custom pre plugins run before the WAF, so their effects
are inspected. The inspected snapshot is therefore not guaranteed to equal
the forwarded request. The evidence comparison must treat "request as
inspected" and "request as forwarded" as distinct.

## Enablement

- Global gate: `waf.enabled` in the gateway config, plus
  `waf.engine_path`, `waf.ruleset_path`, `waf.inspection_limit`,
  `waf.body_limit` (default 10 MiB, experiment limit, not a production
  default), and `waf.pool_size` (reserved for the pooling bead).
- Per-API gate: `waf.enabled` on the API definition (classic and OAS
  surfaces from the config-surface bead). Both flags must be on.
- MCP and JSON-RPC APIs are excluded and the exclusion is logged as an
  unsupported feature; it is never silently omitted.
- Enablement never consults `enable_jsvm` and is independent of
  `CustomMiddleware.Driver`: toggling the WAF changes neither plugin
  availability nor dispatch. No existing JS middleware implementation or
  test was changed by this bead.

## Observable effects at the seam

- Block verdict, block mode: HTTP 403 with the fixed message "Request
  blocked by security policy". The upstream is never reached. No rule IDs,
  anomaly scores, or transaction IDs appear in any client response.
- Block verdict, audit mode: always continues upstream; the status equals
  the no-WAF behaviour; the body reaches the upstream byte-for-byte (the
  middleware never consumes the body until the body-ABI bead lands).
- Inspection internal failure: per-API failure policy applies. Fail-open
  continues upstream; fail-closed returns HTTP 503 with the fixed message
  "Request rejected by security policy" and never reaches upstream. The
  failure detail (typed wafjs failure, engine error text) stays in gateway
  logs only.
- A failed engine build (missing or invalid artifacts) leaves the host
  inactive; every inspection then applies the failure policy until a
  reload builds a working engine. On a successful reload, `processSpec`
  builds the replacement host before the proxy-mux swap; the old spec's
  `Unload` hook closes its host only after that swap.
- Decision detail (mode, verdict, enforced, anomaly score, matched rule
  IDs, inspection scope, skip reason) is logged per request. The full
  shared log-contract record lands with the log-record bead.

## Stage status recorded at this bead

- The committed stub engine allows every request, so corpus attack
  expectations still classify `unexpected_failure` (detection not yet
  claimed) and the benign case passes. The Track still claims no corpus
  `required_features`; body inspection, decompression, rule exclusions,
  libinjection operators, and protocol features remain unclaimed.
- `waf.body_limit` is resolved (per-API override over the global default)
  but not yet enforced; enforcement lands with the body-ABI bead.
- `waf.pool_size` is recorded but unused; the host uses one fresh runtime
  per inspection.
