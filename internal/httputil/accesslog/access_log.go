package accesslog

import (
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/request"
)

// Record is a representation of a transaction log in the Gateway.
type Record struct {
	fields logrus.Fields
}

// NewRecord returns an Record object.
func NewRecord(apiID string, orgId string) *Record {
	fields := logrus.Fields{
		"APIID":  apiID,
		"OrgID":  orgId,
		"prefix": "access-log",
	}
	return &Record{
		fields: fields,
	}
}

// WithLatency sets the latency of the Record.
func (a *Record) WithLatency(latency *analytics.Latency) *Record {
	if latency != nil {
		a.fields["TotalLatency"] = latency.Total
		a.fields["UpstreamLatency"] = latency.Upstream
	}
	return a
}

// WithAuthToken sets the access token from the request under APIKey.
// The access token is obfuscated, or hashed depending on passed arguments.
func (a *Record) WithAuthToken(req *http.Request, hashKeys bool, obfuscate func(string) string) *Record {
	if req != nil {
		token := ctx.GetAuthToken(req)
		if !hashKeys {
			a.fields["APIKey"] = obfuscate(token)
		} else {
			a.fields["APIKey"] = crypto.HashKey(token, hashKeys)
		}
	}
	return a
}

// WithRequest sets the request of the Record.
func (a *Record) WithRequest(req *http.Request) *Record {
	if req != nil {
		upstreamAddress := &url.URL{
			Scheme:   req.URL.Scheme,
			Host:     req.URL.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		a.fields["ClientIP"] = request.RealIP(req)
		a.fields["ClientRemoteAddr"] = req.RemoteAddr
		a.fields["Host"] = req.Host
		a.fields["Method"] = req.Method
		a.fields["Proto"] = req.Proto
		a.fields["RequestURI"] = req.RequestURI
		a.fields["UpstreamAddress"] = upstreamAddress.String()
		a.fields["UpstreamPath"] = req.URL.Path
		a.fields["UpstreamURI"] = req.URL.RequestURI()
		a.fields["UserAgent"] = req.UserAgent()
	}
	return a
}

// WithResponse sets the request of the Record.
func (a *Record) WithResponse(resp *http.Response) *Record {
	if resp != nil {
		a.fields["StatusCode"] = resp.StatusCode
	}
	return a
}

// Fields returns a logrus.Fields intended for logging.
func (a *Record) Fields() logrus.Fields {
	return a.fields
}
