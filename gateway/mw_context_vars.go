package gateway

import (
	"context"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/internal/uuid"

	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"
)

type MiddlewareContextVars struct {
	*BaseMiddleware
}

func (m *MiddlewareContextVars) Name() string {
	return "MiddlewareContextVars"
}

func (m *MiddlewareContextVars) EnabledForSpec() bool {
	return m.Spec.EnableContextVars
}

const traceIDVarKey = "tyk_trace_id"

func (m *MiddlewareContextVars) addTraceIDToContextVars(
	ctx context.Context,
	vars map[string]interface{},
) map[string]interface{} {
	if !m.Gw.GetConfig().OpenTelemetry.Enabled {
		return vars
	}

	id := otel.ExtractTraceID(ctx)
	if id == "" {
		return vars
	}

	if vars == nil {
		vars = make(map[string]interface{}, 1)
	}
	vars[traceIDVarKey] = id
	return vars
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MiddlewareContextVars) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	parseForm(r)

	contextDataObject := map[string]interface{}{
		"request_data": r.Form, // Form params (map[string][]string)
		"headers":      map[string][]string(r.Header),
		"headers_Host": r.Host,
		"path_parts":   strings.Split(r.URL.Path, "/"), // Path parts
		"path":         r.URL.Path,                     // path data
		"remote_addr":  request.RealIP(r),              // IP
		"request_id":   uuid.New(),                     //Correlation ID
	}

	contextDataObject = m.addTraceIDToContextVars(r.Context(), contextDataObject)

	for hname, vals := range r.Header {
		n := "headers_" + strings.Replace(hname, "-", "_", -1)
		contextDataObject[n] = vals[0]
	}

	for _, c := range r.Cookies() {
		name := "cookies_" + strings.Replace(c.Name, "-", "_", -1)
		contextDataObject[name] = c.Value
	}

	for key, vals := range r.Form {
		name := "request_data_" + strings.Replace(key, "-", "_", -1)
		if len(vals) > 0 {
			contextDataObject[name] = vals[0]
		}
	}

	ctxSetData(r, contextDataObject)

	return nil, http.StatusOK
}
