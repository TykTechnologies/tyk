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

// WithAuthToken sets the access token from the request under APIKey.
// The access token is obfuscated, or hashed depending on passed arguments.
func (a *Record) WithAuthToken(req *http.Request, hashKeys bool, obfuscate func(string) string) *Record {
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

// WithClientIP sets the client address of the Record.
func (a *Record) WithClientIP(req *http.Request) *Record {
	if req != nil {
		a.fields["client_ip"] = request.RealIP(req)
		a.fields["client_remote_addr"] = req.RemoteAddr
	}
	return a
}

// WithLatency sets the latency data of the Record.
func (a *Record) WithLatency(latency *analytics.Latency) *Record {
	if latency != nil {
		a.fields["total_latency"] = latency.Total
		a.fields["upstream_latency"] = latency.Upstream
	}
	return a
}

// WithRequest sets the default request of the Record.
func (a *Record) WithRequest(req *http.Request) *Record {
	if req != nil {
		a.fields["host"] = req.Host
		a.fields["method"] = req.Method
		a.fields["protocol"] = req.Proto
		a.fields["user_agent"] = req.UserAgent()
	}
	return a
}

// WithRequestURI sets the request URI of the Record. May contain sensitive data such as
// query parameters etc.
func (a *Record) WithRequestURI(req *http.Request) *Record {
	if req != nil {
		a.fields["request_uri"] = req.RequestURI
	}
	return a
}

// WithResponse sets the response data of the Record.
func (a *Record) WithResponse(resp *http.Response) *Record {
	if resp != nil {
		a.fields["status_code"] = resp.StatusCode
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

// WithUpstreamURI sets the upstream URI of the Record. May contain sensitive data such as
// query parameters etc.
func (a *Record) WithUpstreamURI(req *http.Request) *Record {
	if req != nil {
		a.fields["upstream_uri"] = req.URL.RequestURI()
	}
	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields() logrus.Fields {
	return a.fields
}
