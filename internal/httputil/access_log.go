package httputil

import (
	"net/http"
	"net/url"

	"github.com/TykTechnologies/tyk/request"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

// AccessLogRecord is a representation of a transaction log in the Gateway
type AccessLogRecord logrus.Fields

// NewAccessLogRecord returns an AccessLogRecord object
func NewAccessLogRecord(apiID string, apiKey string, orgId string) *AccessLogRecord {
	a := &AccessLogRecord{
		"APIID":  apiID,
		"APIKey": apiKey,
		"OrgID":  orgId,
		"prefix": "access-log",
	}

	return a
}

// WithLatency sets the latency of the AccessLogRecord
func (a *AccessLogRecord) WithLatency(latency *analytics.Latency) *AccessLogRecord {
	if latency != nil {
		(*a)["TotalLatency"] = latency.Total
		(*a)["UpstreamLatency"] = latency.Upstream
	}
	return a
}

// WithRequest sets the request of the AccessLogRecord
func (a *AccessLogRecord) WithRequest(req *http.Request) *AccessLogRecord {
	if req != nil {
		(*a)["ClientIP"] = request.RealIP(req)
		(*a)["ClientRemoteAddr"] = req.RemoteAddr
		(*a)["Host"] = req.Host
		(*a)["Method"] = req.Method
		(*a)["Proto"] = req.Proto
		(*a)["RequestURI"] = req.RequestURI
		(*a)["UpstreamAddress"] = (&url.URL{
			Scheme:   req.URL.Scheme,
			Host:     req.URL.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}).String()
		(*a)["UpstreamPath"] = req.URL.Path
		(*a)["UpstreamURI"] = req.URL.RequestURI()
		(*a)["UserAgent"] = req.UserAgent()
	}
	return a
}

// WithResponse sets the request of the AccessLogRecord
func (a *AccessLogRecord) WithResponse(resp *http.Response) *AccessLogRecord {
	if resp != nil {
		(*a)["StatusCode"] = resp.StatusCode
	}
	return a
}

// Fields converts the AccessLogRecord as a logrus.Fields object
func (a *AccessLogRecord) Fields() logrus.Fields {
	return logrus.Fields(*a)
}
