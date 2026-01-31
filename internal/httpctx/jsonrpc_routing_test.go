package httpctx

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONRPCRoutingState_SetAndGet(t *testing.T) {
	r := httptest.NewRequest("POST", "/test", nil)

	// Initially nil
	assert.Nil(t, GetJSONRPCRoutingState(r))

	// Set state
	state := &JSONRPCRoutingState{
		Method:       "tools/call",
		Params:       json.RawMessage(`{"name":"test"}`),
		ID:           123,
		NextVEM:      "/mcp-tool:weather.getForecast",
		OriginalPath: "/api",
		VEMChain:     []string{"/json-rpc-method:tools/call", "/mcp-tool:weather.getForecast"},
		VisitedVEMs:  []string{},
	}
	SetJSONRPCRoutingState(r, state)

	// Retrieve state
	retrieved := GetJSONRPCRoutingState(r)
	require.NotNil(t, retrieved)
	assert.Equal(t, "tools/call", retrieved.Method)
	assert.Equal(t, "/mcp-tool:weather.getForecast", retrieved.NextVEM)
	assert.Equal(t, "/api", retrieved.OriginalPath)
}

func TestIsRoutingComplete(t *testing.T) {
	tests := []struct {
		name     string
		state    *JSONRPCRoutingState
		expected bool
	}{
		{
			name:     "nil state - complete",
			state:    nil,
			expected: true,
		},
		{
			name: "empty NextVEM - complete",
			state: &JSONRPCRoutingState{
				NextVEM: "",
			},
			expected: true,
		},
		{
			name: "has NextVEM - not complete",
			state: &JSONRPCRoutingState{
				NextVEM: "/mcp-tool:test",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/test", nil)
			if tt.state != nil {
				SetJSONRPCRoutingState(r, tt.state)
			}
			assert.Equal(t, tt.expected, IsRoutingComplete(r))
		})
	}
}

func TestRoutingStatePreservation(t *testing.T) {
	r := httptest.NewRequest("POST", "/test", nil)

	state := &JSONRPCRoutingState{
		Method:       "tools/call",
		NextVEM:      "/mcp-tool:weather.getForecast",
		OriginalPath: "/api",
		VEMChain:     []string{"/op", "/tool"},
		VisitedVEMs:  []string{},
	}
	SetJSONRPCRoutingState(r, state)

	// Simulate routing progression
	retrieved := GetJSONRPCRoutingState(r)
	retrieved.NextVEM = "" // Clear after routing
	retrieved.VisitedVEMs = append(retrieved.VisitedVEMs, "/op")

	// Verify changes persist
	final := GetJSONRPCRoutingState(r)
	assert.Equal(t, "", final.NextVEM)
	assert.Equal(t, []string{"/op"}, final.VisitedVEMs)
}

func TestRecordVEMVisit(t *testing.T) {
	state := &JSONRPCRoutingState{
		VisitedVEMs: []string{},
	}

	RecordVEMVisit(state, "/json-rpc-method:tools/call")
	assert.Equal(t, []string{"/json-rpc-method:tools/call"}, state.VisitedVEMs)

	RecordVEMVisit(state, "/mcp-tool:weather.getForecast")
	assert.Equal(t, []string{
		"/json-rpc-method:tools/call",
		"/mcp-tool:weather.getForecast",
	}, state.VisitedVEMs)

	// Nil state should not panic
	RecordVEMVisit(nil, "/test")
}
