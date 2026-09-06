# MCP server discovery

Native `server/discover` responses intersect upstream versions with the same endpoint support contract used by ingress, in Gateway order. Synthetic endpoints remain limited to the baseline SDK's legacy versions until TT-18004 adds their modern runtime.

JSON and complete SSE events share capability filtering. Method policies remove unavailable capabilities; filtering individual tools does not remove the `tools` capability. Identity, instructions, result type, extensions and unknown metadata survive rewriting. Credential-dependent results use `cacheScope: "private"` and `ttlMs: 0`, including responses where no capability is removed. Cache lookup is bypassed for applicable credential method policies. Static version intersection alone preserves upstream cache hints.

Validation: `GOWORK=off go test -count=1 ./internal/mcp/... ./gateway -run 'MCP|Discovery|SSETap'`. Gateway's embedded SDK remains v1.6.0.
