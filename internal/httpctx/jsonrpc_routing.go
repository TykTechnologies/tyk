package httpctx

import (
	"encoding/json"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

// JSONRPCRoutingState tracks sequential VEM routing for JSON-RPC requests.
// This is a GENERIC linked-list traversal - no protocol-specific logic.
// It simply stores "what's next" in the routing chain.
type JSONRPCRoutingState struct {
	// Original JSON-RPC request data (preserved across internal calls)
	Method string          // JSON-RPC method (e.g., "tools/call", "ping")
	Params json.RawMessage // JSON-RPC params
	ID     interface{}     // JSON-RPC ID

	// Generic routing state - just follow the chain
	NextVEM      string // Next VEM path to route to (empty = done)
	OriginalPath string // Original request path (for telemetry)

	// Metadata for debugging and telemetry
	VEMChain    []string // Full planned chain (for debugging)
	VisitedVEMs []string // VEMs we've visited so far
}

var routingStateValue = NewValue[*JSONRPCRoutingState](ctx.JSONRPCRoutingState)

// SetJSONRPCRoutingState stores routing state in request context.
func SetJSONRPCRoutingState(r *http.Request, state *JSONRPCRoutingState) {
	routingStateValue.Set(r, state)
}

// GetJSONRPCRoutingState retrieves routing state from request context.
// Returns nil if no routing state exists.
func GetJSONRPCRoutingState(r *http.Request) *JSONRPCRoutingState {
	return routingStateValue.Get(r)
}

// IsRoutingComplete returns true when there's no next VEM to route to.
func IsRoutingComplete(r *http.Request) bool {
	state := GetJSONRPCRoutingState(r)
	return state == nil || state.NextVEM == ""
}

// RecordVEMVisit adds the current VEM to the visited list for telemetry.
func RecordVEMVisit(state *JSONRPCRoutingState, vemPath string) {
	if state == nil {
		return
	}
	state.VisitedVEMs = append(state.VisitedVEMs, vemPath)
}
