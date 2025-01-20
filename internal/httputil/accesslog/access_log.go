package accesslog

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/crypto"
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
	if req != nil {
		token := ctx.GetAuthToken(req)
		if !hashKeys {
			a.fields["api_key"] = obfuscate(token)
		} else {
			a.fields["api_key"] = crypto.HashKey(token, hashKeys)
		}
	}
	return a
}

// WithClientIP sets the client ip of the Record.
func (a *Record) WithClientIP(req *http.Request) *Record {
	if req != nil {
		a.fields["client_ip"] = request.RealIP(req)
	}
	return a
}

// WithHost sets the host of the Record.
func (a *Record) WithHost(req *http.Request) *Record {
	if req != nil {
		a.fields["host"] = req.Host
	}
	return a
}

// WithLatencyTotal sets the total latency of the Record.
func (a *Record) WithLatencyTotal(latency *analytics.Latency) *Record {
	if latency != nil {
		a.fields["latency_total"] = latency.Total
	}
	return a
}

// WithMethod sets the request method of the Record.
func (a *Record) WithMethod(req *http.Request) *Record {
	if req != nil {
		a.fields["method"] = req.Method
	}
	return a
}

// WithRemoteAddr sets the client remote address of the Record.
func (a *Record) WithRemoteAddr(req *http.Request) *Record {
	if req != nil {
		a.fields["remote_addr"] = req.RemoteAddr
	}
	return a
}

// WithPath sets the path of the Record.
func (a *Record) WithPath(req *http.Request) *Record {
	if req != nil {
		a.fields["path"] = req.URL.Path
	}
	return a
}

// WithProtocol sets the request protocol of the Record.
func (a *Record) WithProtocol(req *http.Request) *Record {
	if req != nil {
		a.fields["protocol"] = req.Proto
	}
	return a
}

// WithStatus sets the response status of the Record.
func (a *Record) WithStatus(resp *http.Response) *Record {
	if resp != nil {
		a.fields["status"] = resp.StatusCode
	}
	return a
}

// WithUpstreamAddress sets the upstream address of the Record.
func (a *Record) WithUpstreamAddress(req *http.Request) *Record {
	if req != nil {
		// Default upstream address
		upstreamAddress := &url.URL{
			Scheme: req.URL.Scheme,
			Host:   req.URL.Host,
			Path:   req.URL.Path,
		}

		a.fields["upstream_address"] = upstreamAddress.String()
	}
	return a
}

// WithUpstreamLatency sets the upstream latency of the Record.
func (a *Record) WithUpstreamLatency(latency *analytics.Latency) *Record {
	if latency != nil {
		a.fields["upstream_latency"] = latency.Upstream
	}
	return a
}

// WithUserAgent sets the user agent of the Record.
func (a *Record) WithUserAgent(req *http.Request) *Record {
	if req != nil {
		a.fields["user_agent"] = req.UserAgent()
	}
	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields() logrus.Fields {
	return a.fields
}

// Filter filters the input logrus fields and retains only the allowed fields.
func Filter(in *logrus.Fields, allowedFields []string) *logrus.Fields {
	// Create a map to quickly check if a field is allowed.
	allowed := make(map[string]struct{}, len(allowedFields))
	for _, field := range allowedFields {
		allowed[strings.ToLower(field)] = struct{}{}
	}

	// Create a new logrus.Fields to store the filtered fields.
	filtered := logrus.Fields{}

	// Add the "prefix" field by default, if it exists in the input
	if prefix, exists := (*in)["prefix"]; exists {
		filtered["prefix"] = prefix
	}

	// Filter keys based on config
	for key, value := range *in {
		if _, exists := allowed[strings.ToLower(key)]; exists {
			filtered[key] = value
		}
	}

	return &filtered
}
