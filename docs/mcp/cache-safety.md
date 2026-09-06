# MCP credential-dependent caching (TT-18007)

Applicable credential filtering makes every page a private representation, even
when the page is empty or every item on that page is allowed. List and initialize
results rewritten under access rules carry `cacheScope: "private"` and `ttlMs: 0`.
This resolves the ticket's ambiguous use of “unchanged”: absence of applicable
rules preserves upstream bytes and hints; absence of removals is insufficient.

Gateway bypasses cache lookup for relevant credential rules and prevents writes
of edited responses. Streaming MCP responses are not cached. Unrelated HTTP APIs
retain their caching behavior. IDs, unknown envelope/result fields, item order,
and pagination cursors survive rewriting.

When an MCP filter is attached, the SSE tap rejects events exceeding 1 MiB and
incomplete final events without forwarding their buffered bytes. This safeguard
does not add stream idle deadlines. Other SSE traffic retains existing behavior.

Validation: `GOWORK=off go test -tags 'goplugin dev' -count=1 ./internal/mcp/... ./gateway -run 'Test.*(MCP|SSE|Filter|CredentialDependent|RedisCacheMiddleware_Bypasses|ResponseCacheMiddleware_Skips)'`.
Race coverage: `GOWORK=off go test -race -tags 'goplugin dev' -count=1 ./gateway -run 'TestSSETap|TestMCPListFilterSSE'`.
