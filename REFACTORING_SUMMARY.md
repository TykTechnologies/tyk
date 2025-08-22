# Dashboard Request Recovery Refactoring

## Summary
This refactoring reduces ~120 lines of repetitive error handling code across `api_definition.go` and `policy.go` to a shared, maintainable solution with proper bounded retries.

## Key Improvements

### Before: 6 Repetitive Error Handling Blocks
- **api_definition.go**: 3 recovery blocks (network error, 403 nonce, EOF read)
- **policy.go**: 3 recovery blocks (network error, 403 nonce, EOF read)
- **Problems**: 
  - Code duplication makes maintenance harder
  - Unbounded recursion risk
  - Inconsistent logging
  - Body consumed on 403 errors

### After: Centralized Recovery Logic
- **New file**: `dashboard_recovery.go` (~120 lines)
- **Refactored methods**: Each reduced by ~60 lines
- **Benefits**:
  - Single source of truth for recovery logic
  - Bounded 2-attempt retry policy (no recursion)
  - Preserved response body for callers
  - Consistent error handling and logging
  - Easier to extend (e.g., add backoff, metrics)

## Files Changed

### New Files
1. `gateway/dashboard_recovery.go` - Shared recovery helpers
2. `gateway/api_definition_refactored.go` - Example refactored implementation
3. `gateway/policy_refactored.go` - Example refactored implementation

### Key Functions in dashboard_recovery.go
- `executeDashboardRequestWithRecovery()` - Main request wrapper with 2-attempt retry
- `HandleDashboardResponseReadError()` - EOF error recovery helper
- `attemptDashboardRecovery()` - Re-registration logic
- Helper predicates: `shouldRetryOnNetworkError()`, `isNonceRelatedError()`, `isEOFError()`

## Code Comparison

### Before (api_definition.go - 1 of 3 blocks):
```go
if err != nil {
    if a.Gw.DashService != nil {
        log.Warning("Network error detected during API definitions fetch...")
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        
        if regErr := a.Gw.DashService.Register(ctx); regErr != nil {
            log.Error("Failed to re-register node after network error: ", regErr)
            return nil, err
        }
        log.Info("Node re-registered successfully...")
        
        return a.FromDashboardService(endpoint) // RECURSIVE!
    }
    return nil, err
}
```

### After:
```go
// Build request function for recovery helper
buildReq := func() (*http.Request, error) {
    // ... build request with fresh nonce
}

// Execute request with automatic recovery (2-attempt bounded)
resp, err := a.Gw.executeDashboardRequestWithRecovery(buildReq, "API definitions fetch")
if err != nil {
    return nil, err
}
```

## Benefits for Code Review

1. **Reduced Cognitive Load**: Reviewers see business logic, not error handling noise
2. **Clear Intent**: Method names clearly express recovery behavior
3. **Consistent Patterns**: Same recovery approach everywhere
4. **Safer Code**: Bounded retries prevent infinite loops
5. **Better Testing**: Can unit test recovery logic in isolation
6. **Future-Proof**: Easy to add metrics, circuit breakers, or backoff

## Migration Path

To apply this refactoring:

1. Add `dashboard_recovery.go` to the codebase
2. Replace the method implementations in `api_definition.go` and `policy.go`
3. Run existing tests to verify behavior preservation
4. Consider adding metrics for recovery attempts (future enhancement)

## Potential Future Enhancements

- Add `singleflight.Group` to prevent re-registration storms
- Add exponential backoff for retries
- Emit metrics for recovery attempts/successes/failures
- Consider making retry count configurable