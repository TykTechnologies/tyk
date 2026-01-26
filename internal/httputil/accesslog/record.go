package accesslog

import (
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

// Record is a representation of a transaction log in the Gateway.
type Record struct {
	fields logrus.Fields
}

// NewRecord returns a Record object.
func NewRecord() *Record {
	fields := logrus.Fields{
		"prefix": "access-log",
	}
	return &Record{
		fields: fields,
	}
}

// WithApiKey sets the access token from the request under APIKey.
// The access token is obfuscated, or hashed depending on passed arguments.
func (a *Record) WithApiKey(req *http.Request, hashKeys bool, obfuscate func(string) string) *Record {
	token := ctx.GetAuthToken(req)
	if !hashKeys {
		a.fields["api_key"] = obfuscate(token)
	} else {
		a.fields["api_key"] = crypto.HashKey(token, hashKeys)
	}
	return a
}

// WithRequest fills fields from the http request.
func (a *Record) WithRequest(req *http.Request, latency analytics.Latency) *Record {
	upstreamAddress := &url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   req.URL.Path,
	}

	// Keep the sort in sync with config.AccessLog.Template godoc.
	a.fields["client_ip"] = request.RealIP(req)
	a.fields["host"] = req.Host
	a.fields["latency_total"] = latency.Total
	a.fields["latency_gateway"] = latency.Gateway
	a.fields["method"] = req.Method
	a.fields["path"] = req.URL.Path
	a.fields["protocol"] = req.Proto
	a.fields["remote_addr"] = req.RemoteAddr
	a.fields["upstream_addr"] = upstreamAddress.String()
	a.fields["upstream_latency"] = latency.Upstream
	a.fields["user_agent"] = req.UserAgent()
	return a
}

// WithResponse fills response details into the log fields.
func (a *Record) WithResponse(resp *http.Response) *Record {
	a.fields["status"] = resp.StatusCode
	return a
}

// WithTraceID adds the OpenTelemetry trace ID to the access log record.
// The trace ID is only added if a trace context exists in the request.
func (a *Record) WithTraceID(req *http.Request) *Record {
	traceID := otel.ExtractTraceID(req.Context())
	if traceID != "" {
		a.fields["trace_id"] = traceID
	}
	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields(allowedKeys []string) logrus.Fields {
	return Filter(a.fields, allowedKeys)
}
