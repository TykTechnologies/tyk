# Conditional Middleware — Progress Tracker

## Done

### Expression Compiler (`internal/condition/`)
- [x] Lexer — tokenizer with 14 token types (IDENT, DOT, STRING, AND, OR, NOT, EQ, NEQ, CONTAINS, MATCHES, etc.)
- [x] Parser — recursive descent: `parseOr → parseAnd → parseNot → parsePrimary → parseComparison`
- [x] Compiler — AST to `ConditionFunc` closures, regex compiled at parse time
- [x] Data sources: `request.method`, `request.path`, `request.headers["K"]`, `request.params["K"]`, `context["key"]`, `session.metadata["key"]`
- [x] Operators: `==`, `!=`, `contains`, `matches` (regex)
- [x] Logical: `&&`, `||`, `!`, parentheses
- [x] 21 unit tests — all passing
- [x] 5 benchmarks — all 0 allocs/op, 2.6–56ns

### Data Model — `RateLimitMeta.Condition` (`apidef/api_definitions.go`)
- [x] Added `Condition string` field with bson/json omitempty tags
- [x] JSON round-trip test
- [x] Backward compatibility test (missing key → empty string)

### Validation — `RuleValidateConditions` (`apidef/validator.go`)
- [x] Validates all `RateLimitMeta.Condition` expressions compile
- [x] Registered in `DefaultValidationRuleSet`
- [x] 4 tests: valid, empty, invalid syntax, bad regex

### Load-Time Validation (`gateway/api_loader.go`)
- [x] `skipSpecBecauseInvalid()` compiles all rate limit conditions; rejects API on error

### API-Level Middleware Condition (`gateway/middleware.go`)
- [x] `BaseMiddleware.Condition` / `conditionFunc` / `CompileCondition()`
- [x] Condition check in `createMiddleware()` closure — skips to `next.ServeHTTP` if false
- [x] Panic recovery (fail-closed: runs middleware on panic)
- [x] `safeEvalCondition()` helper
- [x] `condition.ContextDataKey` set via `init()` to `ctx.ContextData`

### Response Handler Condition (`gateway/middleware.go`)
- [x] `BaseTykResponseHandler.Condition` / `conditionFunc` / `CompileCondition()`
- [x] Condition check in `handleResponseChain()` — skips handler if false
- [x] Panic recovery (fail-closed: runs handler on panic)

### Per-Entry Rate Limit Condition (`gateway/mw_api_rate_limit.go`)
- [x] `URLSpec.RateLimitConditionFunc` field (`gateway/model_urlspec.go`)
- [x] Compiled in `compileRateLimitPathsSpec()` (`gateway/api_definition.go`)
- [x] Checked in `getSession()` — falls back to global rate limit if condition false
- [x] 9 middleware condition tests passing

### OAS Round-Trip (`apidef/oas/upstream.go`)
- [x] `RateLimitEndpoint` changed from type alias to explicit struct with `Condition` field
- [x] `Fill()` and `ExtractTo()` updated to include `Condition`
- [x] `internal/oasbuilder/builder.go` updated for new struct type
- [x] 4 round-trip tests passing

### Live Gateway Testing
- [x] Header-based condition: `request.headers["X-Apply-Limit"] == "true"` — rate limit only with header
- [x] Method-based condition: `request.method == "POST"` — POST rate-limited, GET unlimited
- [x] Regex path condition: `request.path matches "^/test/path-regex"` — rate limit on matching paths
- [x] Invalid condition: API rejected at load time, 404 returned, clear error in logs

## TODO — Extend to All Per-Endpoint Middleware Types

### Approach
Instead of adding `Condition` to 15+ individual structs and modifying each middleware, add a **generic `ConditionFunc` on `URLSpec`** and check it in `CheckSpecMatchesStatus` / `FindSpecMatchesStatus`. This single change makes conditions work for ALL middleware types automatically.

### Steps

- [ ] Add `Condition string` field to all per-endpoint meta structs in `apidef/api_definitions.go`:
  - [ ] `EndPointMeta` (Ignored, WhiteList, BlackList)
  - [ ] `CacheMeta` (AdvanceCacheConfig)
  - [ ] `TemplateMeta` (Transform, TransformResponse)
  - [ ] `HeaderInjectionMeta` (TransformHeader, TransformResponseHeader)
  - [ ] `HardTimeoutMeta`
  - [ ] `RequestSizeMeta`
  - [ ] `CircuitBreakerMeta`
  - [ ] `URLRewriteMeta`
  - [ ] `MethodTransformMeta`
  - [ ] `MockResponseMeta`
  - [ ] `TrackEndpointMeta`
  - [ ] `ValidatePathMeta` / `ValidateRequestMeta`
  - [ ] `VirtualMeta` / `GoPluginMeta` / `TransformJQMeta` / `PersistGraphQLMeta`

- [ ] Replace `URLSpec.RateLimitConditionFunc` with generic `URLSpec.ConditionFunc` (`gateway/model_urlspec.go`)

- [ ] Add condition check in `CheckSpecMatchesStatus()` and `FindSpecMatchesStatus()` (`gateway/model_apispec.go`)
  - After path+method match, evaluate `ConditionFunc`; if false, `continue` to next entry

- [ ] Extract `compileConditionForSpec()` helper in `gateway/api_definition.go`

- [ ] Call `compileConditionForSpec()` in ALL `compile*PathsSpec` functions:
  - [ ] `compileExtendedPathSpec` (whitelist/blacklist/ignored)
  - [ ] `compileCachedPathSpec`
  - [ ] `compileTransformPathSpec`
  - [ ] `compileInjectedHeaderSpec`
  - [ ] `compileMethodTransformSpec`
  - [ ] `compileTimeoutPathSpec`
  - [ ] `compileRequestSizePathSpec`
  - [ ] `compileCircuitBreakerPathSpec`
  - [ ] `compileURLRewritesPathSpec`
  - [ ] `compileRateLimitPathsSpec` (update existing)
  - [ ] `compileMockResponsePathSpec`
  - [ ] Others as needed

- [ ] Extend `RuleValidateConditions` to validate conditions on ALL ExtendedPaths fields

- [ ] Extend `skipSpecBecauseInvalid` to validate conditions on ALL ExtendedPaths fields

- [ ] Update `mw_api_rate_limit.go` — remove explicit `RateLimitConditionFunc` check (now handled by `FindSpecMatchesStatus`)

- [ ] Tests:
  - [ ] JSON round-trip for representative structs (EndPointMeta, HardTimeoutMeta, HeaderInjectionMeta)
  - [ ] `CheckSpecMatchesStatus` returns false when condition is false
  - [ ] `FindSpecMatchesStatus` skips entries when condition is false
  - [ ] Validation rule tests for non-RateLimit conditions

- [ ] Live test: rebuild gateway, test with header injection + condition via curl

## Files Inventory

| File | Status | Notes |
|---|---|---|
| `internal/condition/condition.go` | ✅ new | Expression compiler |
| `internal/condition/lexer.go` | ✅ new | Tokenizer |
| `internal/condition/parser.go` | ✅ new | Recursive descent parser |
| `internal/condition/condition_test.go` | ✅ new | 21 tests |
| `internal/condition/bench_test.go` | ✅ new | 5 benchmarks |
| `apidef/api_definitions.go` | ✅ modified | `RateLimitMeta.Condition` (TODO: add to other structs) |
| `apidef/api_definitions_test.go` | ✅ modified | JSON round-trip tests |
| `apidef/validator.go` | ✅ modified | `RuleValidateConditions` (TODO: extend to all) |
| `apidef/validator_test.go` | ✅ modified | Validation tests |
| `apidef/oas/upstream.go` | ✅ modified | `RateLimitEndpoint` struct with Condition |
| `apidef/oas/upstream_test.go` | ✅ modified | OAS round-trip tests |
| `gateway/middleware.go` | ✅ modified | BaseMiddleware + response handler conditions |
| `gateway/middleware_condition_test.go` | ✅ new | 9 middleware condition tests |
| `gateway/model_urlspec.go` | ✅ modified | `RateLimitConditionFunc` (TODO: rename to generic) |
| `gateway/model_apispec.go` | 🔲 TODO | Add condition check in match functions |
| `gateway/api_definition.go` | ✅ modified | Compile in `compileRateLimitPathsSpec` (TODO: all others) |
| `gateway/api_loader.go` | ✅ modified | Validate in `skipSpecBecauseInvalid` (TODO: extend) |
| `gateway/mw_api_rate_limit.go` | ✅ modified | Per-entry condition check (TODO: simplify) |
| `internal/oasbuilder/builder.go` | ✅ modified | Fixed type conversion |
