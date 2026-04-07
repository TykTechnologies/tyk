# Task List: Two-Step Path Parameter Matching

## Phase 1: Foundation (no behavioral change)

- [x] **Task 1**: Add `SchemaTypeToRegex` + `PrepareSubSpecRegexp` + `CompileSubSpec` to `internal/httputil/schema_pattern.go` with unit tests
- [x] **Task 2**: Add `subSpec *regexp.Regexp` field + `matchesSubSpec` method to `gateway/model_urlspec.go`
- [x] **Task 3**: Extract path param schemas and compile sub-spec in `compileOASValidateRequestPathSpec`

**Checkpoint 1**: PASSED — All existing tests pass, sub-specs are built.

## Phase 2: Behavioral change

- [x] **Task 4**: Update `FindSpecMatchesStatus` for two-step matching (group → sub-spec → fallback) + `buildRouteForOASPath` for direct route construction
- [x] **Task 5**: Integration tests for overlapping parameterised paths (3 test functions, all pass)

**Checkpoint 2**: PASSED — Two-step matching works end-to-end, all tests pass.

## Phase 3: Extension (optional)

- [ ] **Task 6**: Apply sub-spec compilation to mock response middleware
