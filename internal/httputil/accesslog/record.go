package accesslog

import (
	"net/http"
	"net/url"

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
	token := ctx.GetAuthToken(req)
	if !hashKeys {
		a.fields["api_key"] = obfuscate(token)
	} else {
		a.fields["api_key"] = crypto.HashKey(token, hashKeys)
	}
	return a
}

// WithUpstreamAddress sets the upstream address of the Record.
func (a *Record) WithUpstreamAddress(req *http.Request) *Record {
	// Default upstream address
	upstreamAddress := &url.URL{
		Scheme: req.URL.Scheme,
		Host:   req.URL.Host,
		Path:   req.URL.Path,
	}

	a.fields["upstream_address"] = upstreamAddress.String()
	return a
}

// WithLatency sets the upstream latency of the Record.
func (a *Record) WithLatency(latency *analytics.Latency) *Record {
	a.fields["upstream_latency"] = latency.Upstream
	a.fields["latency_total"] = latency.Total
	return a
}

// WithRequest fills fields from the http request.
func (a *Record) WithRequest(req *http.Request) *Record {
	a.fields["user_agent"] = req.UserAgent()
	a.fields["protocol"] = req.Proto
	a.fields["path"] = req.URL.Path
	a.fields["client_ip"] = request.RealIP(req)
	a.fields["host"] = req.Host
	a.fields["method"] = req.Method
	a.fields["remote_addr"] = req.RemoteAddr
	return a
}

// WithResponse fills response details into the log fields.
func (a *Record) WithResponse(resp *http.Response) *Record {
	a.fields["status"] = resp.StatusCode
	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields(allowedKeys []string) logrus.Fields {
	return Filter(a.fields, allowedKeys)
}
