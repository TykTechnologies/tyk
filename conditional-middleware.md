# Conditional Middleware

## Context and preconditions

Currently, Tyk middleware is either enabled or disabled per-API at configuration time (via `EnabledForSpec()`). There is no way to conditionally execute middleware on a per-request basis. Gateway operators need the ability to skip or execute specific middleware based on runtime request attributes — e.g., only apply rate limiting when a certain header is present, or only run a transform when a query parameter matches a value. This unlocks use cases like A/B testing, gradual rollouts, feature-flagged middleware, and request-attribute-based processing pipelines.

## Product idea

Each middleware entry in the API definition gains an optional `condition` field containing an expression string. Before a middleware's `ProcessRequest` is invoked, the gateway evaluates the condition against the current request context. If the condition evaluates to `false`, the middleware is skipped and the next middleware in the chain runs.

The expression language should support:
- Request headers: `request.headers["X-Feature"] == "enabled"`
- Query params: `request.params["mode"] == "debug"`
- Request path/method: `request.method == "POST"`
- Tyk context variables: `context["jwt_claims_sub"] == "admin"`
- Session metadata: `session.metadata["tier"] == "premium"`
- Logical operators: `&&`, `||`, `!`, parentheses
- Comparison operators: `==`, `!=`, `contains`, `matches` (regex)

> **Note:** `request.body` is explicitly excluded from v1 scope. Headers, params, path, method, context variables, and session metadata cover the vast majority of use cases without the complexity of body parsing (stream consumption, memory overhead for large payloads). Body access may be added in a future iteration.

Example API definition snippet (OAS):
```json
"operations": {
  "get-users": {
    "rateLimit": {
      "enabled": true,
      "rate": 100,
      "per": 60,
      "condition": "request.headers['X-Rate-Limit'] != 'bypass' && session.metadata['tier'] != 'premium'"
    }
  }
}
```

### Data availability by middleware phase

Not all data sources are available at every point in the middleware chain. Data availability is validated **at API load time** (see "Shift-left validation" below) — not at runtime.

| Data source | Pre (pre-auth) | Post-auth | Post | Response |
|---|---|---|---|---|
| `request.headers` | Yes | Yes | Yes | Yes |
| `request.params` | Yes | Yes | Yes | Yes |
| `request.path` | Yes | Yes | Yes | Yes |
| `request.method` | Yes | Yes | Yes | Yes |
| `context.*` | Partial (no auth data yet) | Yes | Yes | Yes |
| `session.*` | No | Yes | Yes | Yes |

### Failure mode: fail-on (fail-closed)

If a condition experiences a runtime panic (defensive only — see shift-left validation), the middleware **executes** (fail-on). This is a security-first design: a broken condition must never silently disable a security middleware like rate limiting or authentication.

A warning log is emitted on runtime panics. This should be extremely rare because the shift-left validation (point 6 below) eliminates the categories of errors that could cause evaluation failures — the only remaining trigger is truly unexpected Go-level panics (nil pointer in a context map, etc.), which indicate a gateway bug and warrant loud logging on every occurrence.

## What we will do

1. **Two-tier condition model** — conditions apply at two levels depending on the middleware type:

   - **API-level conditions** on `BaseMiddleware`: for middleware that operates globally on the API (e.g., analytics, CORS, IP whitelisting). A `Condition` string field and compiled `ConditionFunc` are added to `BaseMiddleware`, evaluated once in `createMiddleware()` (`gateway/middleware.go:112`) before `ProcessRequest`.

   - **Per-entry conditions** on endpoint spec structs: for middleware that dispatches to per-endpoint/per-operation configs inside `ProcessRequest` (e.g., `RateLimitForAPI`, `TransformMiddleware`, `HeaderInjectorMiddleware`). The `condition` field is added to the per-entry spec structs (`RateLimitMeta`, `TransformSpec`, etc. in `apidef/api_definitions.go`), and the compiled `ConditionFunc` is evaluated inside `ProcessRequest` after the endpoint match resolves via `FindSpecMatchesStatus`.

   This two-tier model is necessary because middleware like `RateLimitForAPI` is a single instance serving all endpoints — it resolves the matching `RateLimitMeta` entry inside `ProcessRequest` (via `k.Spec.FindSpecMatchesStatus(r, versionPaths, RateLimit)` at `gateway/mw_api_rate_limit.go`). A condition on `BaseMiddleware` alone cannot distinguish which endpoint entry the condition belongs to.

2. **Hand-rolled condition compiler (zero dependencies)** — build a small recursive descent parser (~200-300 lines) that compiles condition strings into native Go closures at API load time. The expression language is deliberately narrow (6 data sources, 4 comparison ops, 3 logical ops), so a purpose-built parser is straightforward and avoids any external dependency. No bytecode interpretation, no reflection, no `interface{}` boxing — just plain Go function calls.

   The compiled condition has the signature:
   ```go
   type ConditionFunc func(r *http.Request, session *user.SessionState) bool
   ```

3. **Low-allocation request binding via direct accessors** — compiled closures access request data directly (`r.Header.Get()`, `r.URL.Path`, `r.Method`) instead of building intermediate `map[string]interface{}` environments per-request. Note: `r.URL.Query().Get()` allocates on each call (parses `RawQuery`), so conditions using `request.params` will incur allocations — this is inherent to Go's `net/url` and acceptable. Context variables use `ctxGetData(r)` and session metadata uses `ctxGetSession(r)`, but only when the condition actually references them (determined at parse time via static analysis of the expression).

   - **Static data source resolution**: at parse time, detect which data sources the condition references. If a condition only uses `request.headers`, the closure never touches session or context — avoiding unnecessary map lookups.
   - **Regex pre-compilation**: any `matches` operator compiles its regex pattern via `regexp.Compile` at API load time and embeds the `*regexp.Regexp` in the closure. No regex compilation at request time.

4. **Add condition checks in middleware execution paths** — conditions are evaluated at three distinct points:

   - **Request middleware** (`createMiddleware` at `gateway/middleware.go:112`): before calling `mw.ProcessRequest()`, invoke the API-level `ConditionFunc`. If it returns `false`, skip directly to `next.ServeHTTP(w, r)`.

   - **Response middleware** (`handleResponseChain` at `gateway/middleware.go:780`): before calling `handleResponse()` for each `TykResponseHandler`, check its condition via `BaseTykResponseHandler`. If `false`, skip to the next response handler.

   - **Per-entry conditions**: evaluated inside each dispatching middleware's `ProcessRequest` after the endpoint entry is resolved.

   > **Exclusion: inner auth middlewares in `AuthORWrapper`** are explicitly not supported for conditions. `AuthORWrapper` (`gateway/mw_auth_or_wrapper.go`) calls inner auth middlewares' `ProcessRequest` directly — conditionally skipping an auth method is a security anti-pattern (it would selectively unauthenticate requests based on request attributes). If per-auth-method conditions are ever needed, they require a purpose-built design with explicit security review.

5. **Update OAS and Classic API definition schemas** — add the `condition` field to middleware configuration in both `apidef/oas/middleware.go` and classic API definition structs, including per-entry spec structs (`RateLimitMeta`, `TransformSpec`, etc.).

6. **Shift-left validation (load-time, two paths)** — eliminate runtime evaluation failures by catching all errors at API load time:

   - **REST API path** (`validateAPIDef` at `gateway/api.go:3626`): add a `ValidationRule` to `DefaultValidationRuleSet` in `apidef/validator.go` that parses and compiles every condition expression. Invalid syntax, unknown data sources, or invalid regex patterns in `matches` operators are rejected with HTTP 400 and a descriptive error. Additionally, **validate data availability against middleware phase**: if a condition references `session.*` and is attached to a pre-auth middleware, reject it at load time with a clear error explaining that session data is not available in the pre-auth phase.

   - **Gateway reload path** (`processSpec` at `gateway/api_loader.go`): add condition compilation in or after `skipSpecBecauseInvalid` (`gateway/api_loader.go:73`). If any condition fails to compile or references unavailable data for its phase, set `chainDef.Skip = true` and log an error — matching how invalid listen paths are handled. The previous valid API version persists.

   - **Defensive fallback**: if a `ConditionFunc` is somehow nil at chain init time despite a condition being configured (should be impossible after the above), fall back to fail-on (execute middleware) and log a warning. Never crash via `Fatal`.

   This shift-left approach means runtime evaluation failures are structurally eliminated: syntax errors, bad regexes, unknown variables, and data-availability mismatches are all caught before traffic hits the API. The only remaining runtime failure path is a Go-level panic (nil map in context, etc.), which indicates a gateway bug — not a user configuration error — and warrants loud per-request logging.

## Acceptance criteria

- [ ] A middleware with a `condition` that evaluates to `false` is skipped; the request proceeds to the next middleware
- [ ] A middleware with a `condition` that evaluates to `true` (or no condition) executes normally
- [ ] Conditions can reference: request headers, query params, path, method, Tyk context variables, and session metadata
- [ ] Conditions support `&&`, `||`, `!`, `==`, `!=`, `contains`, and `matches` (regex)
- [ ] Invalid condition expressions are rejected at API load/reload time with a descriptive error — via both the REST API validation path (`validateAPIDef`) and the gateway reload path (`skipSpecBecauseInvalid`)
- [ ] Conditions referencing `session.*` on pre-auth middleware are rejected at load time (not deferred to runtime)
- [ ] Conditions referencing `context.*` auth-derived keys on pre-auth middleware are rejected at load time
- [ ] Runtime panics during condition evaluation cause the middleware to execute (fail-on) with a warning log
- [ ] Condition evaluation adds < 1μs per middleware (p99, benchmarked)
- [ ] Conditions referencing only headers, path, or method are zero-alloc; conditions using `request.params` may allocate due to query string parsing (this is inherent to `r.URL.Query()`)
- [ ] Works with both OAS and Classic API definitions
- [ ] Conditions work on request middleware (via `createMiddleware`), response middleware (via `handleResponseChain`), and per-entry dispatching middleware (via spec entry structs)
- [ ] Inner auth middlewares within `AuthORWrapper` do not support conditions (explicitly excluded, documented)
- [ ] Per-entry conditions (e.g., on `RateLimitMeta`) are evaluated inside `ProcessRequest` after endpoint matching, not at the `BaseMiddleware` level

## Testing

- **Unit tests**: Test the expression evaluator/compiler with various condition strings against mock request contexts (headers, params, context vars, session metadata). Test edge cases: empty condition (always run), invalid expressions (error at compile), nil/missing header values (evaluates to `""`, not an error).
- **Unit tests**: Test `createMiddleware` skip logic — verify middleware is bypassed when condition is false, executed when true, and executed on evaluation panic (fail-on).
- **Unit tests**: Test per-entry condition evaluation — verify that a `RateLimitMeta` condition is evaluated after endpoint matching inside `ProcessRequest`, not at the `BaseMiddleware` level.
- **Unit tests**: Test response middleware condition — verify that a response-phase middleware (e.g., `ResponseTransformMiddleware`) is skipped when its condition evaluates to false.
- **Load-time validation tests**: Verify that a condition referencing `session.metadata` on a pre-auth middleware is rejected at API load time with a descriptive error (not deferred to runtime).
- **Load-time validation tests**: Verify that an invalid condition expression (syntax error, bad regex) is rejected via the REST API path (HTTP 400 from `validateAPIDef`) and via the reload path (API skipped, previous version persists).
- **OAS/Classic round-trip tests**: In `apidef/oas/middleware_test.go`, verify `Fill` → `ExtractTo` → `Fill` preserves the `condition` field on all middleware types that support it. Test empty/nil condition produces no diff.
- **Integration tests**: Load an API with conditional middleware via the Gateway API, send requests with varying headers/params, assert middleware executed or was skipped (e.g., rate limit applies vs. doesn't).
- **Benchmark tests**: Measure per-request overhead of condition evaluation to verify < 1μs p99 target. Use `b.ReportAllocs()` to confirm 0 allocs/op for conditions on headers/path/method. Conditions using `request.params` may show allocations from `r.URL.Query()` parsing — this is expected and acceptable.
- **Regression tests**: APIs with no conditions behave identically to current behavior (no regressions).
