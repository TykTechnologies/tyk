package proxy

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/httpctx"
)

// newReq builds a minimal *http.Request with the given self-looping flag
// and (optionally) a calling APIDef stashed via httpctx. Used by every
// table-driven case below.
func newReq(t *testing.T, selfLooping bool, callerAPIID string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", "http://source.example/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if selfLooping {
		httpctx.SetSelfLooping(r, true)
	}
	if callerAPIID != "" {
		r = httpctx.SetCallingSpec(r, &apidef.APIDefinition{APIID: callerAPIID})
	}
	return r
}

func TestCallerAuthEvaluate_AcceptLoopCallersFalse(t *testing.T) {
	c := &CallerAuth{AcceptLoopCallers: false}
	r := newReq(t, true, "proxy-1")
	if got := c.Evaluate(r, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp", got)
	}
}

func TestCallerAuthEvaluate_NotSelfLooping(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	r := newReq(t, false, "proxy-1")
	if got := c.Evaluate(r, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp", got)
	}
}

func TestCallerAuthEvaluate_NoCallingSpec(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	r := newReq(t, true, "" /* no caller stashed */)
	if got := c.Evaluate(r, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp (lookup failure must fail closed)", got)
	}
}

func TestCallerAuthEvaluate_CallerLacksMCPProxyExt(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	r := newReq(t, true, "proxy-1")
	// callerHasMCPProxyExt = false: caller is a non-MCP APIDef looping in.
	if got := c.Evaluate(r, false); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp", got)
	}
}

func TestCallerAuthEvaluate_CallerNotInBackRef(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	// Caller carries the extension, but its APIID is NOT in this
	// source's back-ref — multi-tenant safety must reject.
	r := newReq(t, true, "proxy-other")
	if got := c.Evaluate(r, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp (back-ref miss)", got)
	}
}

func TestCallerAuthEvaluate_TrustHappyPath(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers: true,
		AllowedProxyAPIIDs: map[string]struct{}{
			"proxy-1": {},
			"proxy-2": {},
		},
	}
	r := newReq(t, true, "proxy-2")
	if got := c.Evaluate(r, true); got != DecisionTrust {
		t.Fatalf("decision = %v, want Trust", got)
	}
}

func TestCallerAuthEvaluate_NilReceiver(t *testing.T) {
	var c *CallerAuth
	r := newReq(t, true, "proxy-1")
	if got := c.Evaluate(r, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp on nil receiver", got)
	}
}

func TestCallerAuthEvaluate_NilRequest(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	if got := c.Evaluate(nil, true); got != DecisionNoOp {
		t.Fatalf("decision = %v, want NoOp on nil request", got)
	}
}

func TestParseContextHeader_PresentAndValid(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example/", nil)
	r.Header.Set(HeaderXTykMCPContext, `{"agent_id":"agent-7","proxy_apiid":"proxy-1","tool_name":"users__get","request_id":"req-42","issued_at":1714780800}`)

	got := ParseContextHeader(r)
	want := ContextHeader{
		AgentID:    "agent-7",
		ProxyAPIID: "proxy-1",
		ToolName:   "users__get",
		RequestID:  "req-42",
		IssuedAt:   1714780800,
	}
	if got != want {
		t.Fatalf("ParseContextHeader = %+v, want %+v", got, want)
	}
}

func TestParseContextHeader_Missing(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example/", nil)
	if got := ParseContextHeader(r); got != (ContextHeader{}) {
		t.Fatalf("expected zero ContextHeader, got %+v", got)
	}
}

func TestParseContextHeader_Malformed(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example/", nil)
	r.Header.Set(HeaderXTykMCPContext, `{"agent_id": notjson`)
	// Per RFC §8.4 the header is metadata only; a parse error must
	// not propagate as an error to the caller.
	if got := ParseContextHeader(r); got != (ContextHeader{}) {
		t.Fatalf("expected zero ContextHeader on malformed JSON, got %+v", got)
	}
}

func TestParseContextHeader_Empty(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example/", nil)
	r.Header.Set(HeaderXTykMCPContext, "")
	if got := ParseContextHeader(r); got != (ContextHeader{}) {
		t.Fatalf("expected zero ContextHeader on empty header, got %+v", got)
	}
}

func TestParseContextHeader_NilRequest(t *testing.T) {
	if got := ParseContextHeader(nil); got != (ContextHeader{}) {
		t.Fatalf("expected zero ContextHeader on nil request, got %+v", got)
	}
}

// TestCallerAuthEvaluate_TrustWithMalformedContextHeader covers RFC §15.1's
// "Malformed X-Tyk-MCP-Context -> still trusted" bullet. The trust
// decision is gated by channel signals (self-loop flag + calling APIDef
// back-ref), NOT by the contents of X-Tyk-MCP-Context. The header is
// metadata only (RFC §8.4), so a malformed value must not downgrade Trust.
// ParseContextHeader on the same request returns a zero ContextHeader,
// confirming the agent_id is empty when the header cannot be parsed.
func TestCallerAuthEvaluate_TrustWithMalformedContextHeader(t *testing.T) {
	c := &CallerAuth{
		AcceptLoopCallers:  true,
		AllowedProxyAPIIDs: map[string]struct{}{"proxy-1": {}},
	}
	r := newReq(t, true, "proxy-1")
	r.Header.Set(HeaderXTykMCPContext, `{"agent_id": notjson`)

	if got := c.Evaluate(r, true); got != DecisionTrust {
		t.Fatalf("decision = %v, want Trust (malformed header is metadata, not trust input)", got)
	}
	// Synthetic-session-side concern: agent_id must end up empty.
	if got := ParseContextHeader(r); got != (ContextHeader{}) {
		t.Fatalf("ParseContextHeader = %+v, want zero ContextHeader", got)
	}
}

func TestDecisionString(t *testing.T) {
	cases := []struct {
		d    Decision
		want string
	}{
		{DecisionNoOp, "no-op"},
		{DecisionTrust, "trust"},
		{Decision(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tc.d, got, tc.want)
		}
	}
}
