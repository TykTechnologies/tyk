package apimetrics

import (
	"net/http"

	"github.com/TykTechnologies/tyk/user"
)

// RequestContext bundles all data available at the recording site.
// Fields are extracted at the call site to avoid importing gateway types.
type RequestContext struct {
	Request  *http.Request
	Response *http.Response // upstream response (nil on error path)

	StatusCode          int
	APIID               string
	APIName             string
	OrgID               string
	ListenPath          string
	Token               string // hashed auth token
	APIVersion          string
	IPAddress           string // client IP (resolved by the recording site via request.RealIP)
	ErrorClassification string // response flag string (resolved by the recording site)

	// Latency values in milliseconds.
	LatencyTotal    int64
	LatencyUpstream int64
	LatencyGateway  int64

	Session          *user.SessionState     // nil when unauthenticated or NeedsSession=false
	ContextVariables map[string]interface{} // Tyk context variables (nil when not enabled)
}
