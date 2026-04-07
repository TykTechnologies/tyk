# Plan: Two-Step Path Parameter Matching for ValidateRequest

## Problem

When multiple OAS paths share the same path structure but differ only by path parameter schemas (e.g., `/employees/{prct}` with `pattern: ^[a-z]$` and `/employees/{zd}` with `pattern: [1-9]`), both compile to the same generic regex `^/employees/([^/]+)$`. The gateway returns whichever URLSpec matches first, applying the wrong endpoint's validation rules.

## Desired Behavior

```
Generic regex: /employees/([^/]+)     ← catches all requests
  ├─ /employees/^[a-z]$              → use prct endpoint's validation (header def)
  ├─ /employees/[1-9]                → use zd endpoint's validation (header abc)
  └─ no sub-match                    → reject using last sub-route's rules (fallback)
```

1. `GET /employees/a` → matches generic → matches `^[a-z]$` → validates with prct's rules
2. `GET /employees/1` → matches generic → matches `[1-9]` → validates with zd's rules
3. `GET /employees/ddd111` → matches generic → no sub-match → fallback to last sub-route's rules (rejected)

## Design

### Core Concept: Sub-Specs

URLSpecs that compile to the same generic regex are grouped. Each URLSpec gets an additional **sub-spec regex** compiled from the original schema patterns instead of the generic `([^/]+)`.

### Type-Based Default Patterns

When a path parameter has no explicit `schema.pattern`, we derive a regex from `schema.type`:

| OAS Type    | Default Regex     |
|-------------|-------------------|
| `string`    | `[^/]+`           |
| `number`    | `[0-9]*\.?[0-9]+` |
| `integer`   | `[0-9]+`          |
| `boolean`   | `true\|false`     |
| (no type)   | `[^/]+`           |

### Matching Algorithm Change

`FindSpecMatchesStatus` currently returns the first URLSpec whose generic regex matches. The new behavior:

1. Scan URLSpecs as before (status + method + generic regex match)
2. When a match is found, collect **all** URLSpecs sharing the same generic regex pattern and method
3. Among those, try each one's sub-spec regex against the actual path
4. Return the first sub-spec match
5. If no sub-spec matches, return the **last** URLSpec in the group (fallback/catch-all)

### Files to Change

| File | Change |
|------|--------|
| `gateway/model_urlspec.go` | Add `subSpec *regexp.Regexp` field to URLSpec |
| `gateway/api_definition.go` | Build sub-spec regex during `compileOASValidateRequestPathSpec` |
| `internal/httputil/mux.go` | New function to build path regex from schema patterns |
| `gateway/model_apispec.go` | Update `FindSpecMatchesStatus` for two-step matching |
| `gateway/mw_oas_validate_request_test.go` | New test for overlapping parameterised paths |
| `gateway/mw_oas_validate_request_path_priority_test.go` | New test for sub-spec matching |

### What Does NOT Change

- The primary `spec` regex field — still uses `([^/]+)` for generic matching
- `matchesPath` — unchanged, still uses generic regex
- `sortURLSpecsByPathPriority` — unchanged
- `addStaticPathShields` — unchanged
- Mock response middleware — same pattern applies but is out of scope unless requested
- `processRequestWithFindOperation` (mux-template fallback) — unchanged

## Tasks

### Task 1: Add type-based pattern helper (internal/httputil)

Add a function `SchemaTypeToRegex(schemaType string) string` that maps OAS types to regex patterns. Add a function `PreparePathRegexpFromSchemas(path string, paramSchemas map[string]ParamSchema, prefix, suffix bool) string` that replaces each `{param}` with its schema-derived regex instead of `([^/]+)`.

**Acceptance criteria:**
- `string` → `[^/]+`, `number` → `[0-9]*\.?[0-9]+`, `integer` → `[0-9]+`, `boolean` → `true|false`
- Explicit `pattern` in schema overrides type-based default
- Multiple params in one path each get their own pattern
- Unit tests pass for all type mappings and edge cases

**Verification:** `go test ./internal/httputil/ -run TestPreparePathRegexpFromSchemas`

### Task 2: Add `subSpec` field to URLSpec

Add `subSpec *regexp.Regexp` to the URLSpec struct. This holds the regex compiled from original schema patterns.

**Acceptance criteria:**
- Field added, no existing tests break
- `matchesSubSpec(path string, api *APISpec) bool` method added to URLSpec

**Verification:** `go test ./gateway/ -run TestSortURLSpecsByPathPriority` (existing tests still pass)

### Task 3: Build sub-spec during compilation

In `compileOASValidateRequestPathSpec`, after finding the path and method for an operation, extract path parameter schemas from the OAS spec, build the sub-spec regex using Task 1's function, and store it in the URLSpec.

**Acceptance criteria:**
- Path parameters are extracted from both operation-level and path-item-level parameters
- Sub-spec regex is compiled and stored in `URLSpec.subSpec`
- Paths without path parameters get no sub-spec (nil)
- Existing compilation tests still pass

**Verification:** `go test ./gateway/ -run TestCompileOASValidateRequest`

---

**Checkpoint 1:** Tasks 1-3 complete. Sub-specs are built and stored. No behavioral change yet — `FindSpecMatchesStatus` still uses generic matching. All existing tests pass.

---

### Task 4: Two-step matching in FindSpecMatchesStatus

Update `FindSpecMatchesStatus` to implement the grouping and sub-spec matching logic:

1. On first generic match, collect all URLSpecs with same generic regex pattern string + method
2. If only one in the group, return it (current behavior — no regression)
3. If multiple, try `matchesSubSpec` on each; return first match
4. If no sub-spec matches, return last in the group (fallback)

**Acceptance criteria:**
- Single-endpoint paths behave identically to before (no regression)
- Overlapping parameterised paths dispatch to the correct endpoint
- Fallback to last endpoint when no sub-spec matches
- Static path shields still work (they never have sub-specs)

**Verification:** All existing tests pass + new tests from Task 5

### Task 5: Integration tests for overlapping parameterised paths

Write tests covering the exact scenario from the problem statement:

- `/employees/{prct}` (pattern `^[a-z]$`, requires header `def`)
- `/employees/{zd}` (type `number`, pattern `[1-9]`, requires header `abc`)
- `GET /employees/a` → requires header `def`
- `GET /employees/1` → requires header `abc`
- `GET /employees/ddd111` → rejected (fallback)

Also test:
- Multi-segment overlapping paths: `/dept/{deptId}/employees/{empId}` vs `/dept/{deptId}/employees/{name}`
- Mixed static + parameterised + overlapping: all three coexist correctly

**Verification:** `go test ./gateway/ -run TestValidateRequest_OverlappingParameterisedPaths`

---

**Checkpoint 2:** Tasks 4-5 complete. Two-step matching works end-to-end. All tests pass.

---

### Task 6: Extend to mock response middleware (if needed)

Apply the same sub-spec compilation to `compileOASMockResponsePathSpec` and verify mock responses dispatch correctly for overlapping paths.

**Acceptance criteria:**
- Mock response uses the same two-step matching via shared `FindSpecMatchesStatus`
- Tests verify correct mock body returned for overlapping parameterised paths

**Verification:** `go test ./gateway/ -run TestMockResponse_OverlappingParameterisedPaths`

## Dependency Graph

```
Task 1 (helper functions)
  └──→ Task 2 (URLSpec field)
         └──→ Task 3 (compilation)
                └──→ [Checkpoint 1]
                       └──→ Task 4 (matching logic)
                              └──→ Task 5 (integration tests)
                                     └──→ [Checkpoint 2]
                                            └──→ Task 6 (mock response, optional)
```

## Risks and Mitigations

1. **Performance**: Collecting all specs with the same generic regex adds a linear scan within a linear scan. Mitigation: the number of overlapping paths is typically small (2-3). If needed, pre-group during compilation.

2. **Regex compilation errors**: Malformed schema patterns could fail to compile. Mitigation: log a warning and skip sub-spec (fall back to generic matching, preserving current behavior).

3. **Parameter inheritance**: OAS allows parameters at the path-item level (shared across methods) and at the operation level (method-specific). Both must be considered. Operation-level params override path-item params with the same name.
