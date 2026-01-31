// Package jsonrpc provides utilities for JSON-RPC 2.0 protocol handling.
package jsonrpc

// VEM path prefixes for JSON-RPC routing.
// These are protocol-agnostic and work for any JSON-RPC 2.0 implementation.
const (
	// MethodVEMPrefix is the prefix for operation-level VEMs based on JSON-RPC method names.
	// Format: /json-rpc-method:{method}
	// Example: /json-rpc-method:tools/call, /json-rpc-method:initialize
	//
	// This is protocol-agnostic and used by all JSON-RPC protocols (MCP, A2A, custom).
	MethodVEMPrefix = "/json-rpc-method:"

	// MethodVEMCatchAllPattern is the catch-all pattern for operation-level allowlist blocking.
	// Uses mux-style pattern matching: /json-rpc-method:{rest:.*}
	MethodVEMCatchAllPattern = "/json-rpc-method:{rest:.*}"
)
