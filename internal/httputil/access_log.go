package httputil

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/request"
)

// AccessLogRecord is a representation of a transaction log in the Gateway
type AccessLogRecord struct {
	APIID    string
	APIKey   string
	OrgID    string
	Latency  *analytics.Latency
	Request  *http.Request
	Response *http.Response
}

func NewAccessLogRecord(apiID string, apiKey string, orgId string) *AccessLogRecord {
	return &AccessLogRecord{
		APIID:  apiID,
		APIKey: apiKey,
		OrgID:  orgId,
	}
}

func (a *AccessLogRecord) Logger(log *logrus.Logger) *logrus.Entry {
	// Default fields
	fields := logrus.Fields{
		"APIID":  a.APIID,
		"APIKey": a.APIKey,
		"OrgID":  a.OrgID,
		"prefix": "access-log",
	}

	// Include latency fields if it exists
	if a.Latency != nil {
		fields["TotalLatency"] = a.Latency.Total
		fields["UpstreamLatency"] = a.Latency.Upstream
	}

	// Include request fields if it exists
	if a.Request != nil {
		fields["ClientIP"] = request.RealIP(a.Request)
		fields["ClientRemoteAddr"] = a.Request.RemoteAddr
		fields["Host"] = a.Request.Host
		fields["Method"] = a.Request.Method
		fields["Proto"] = a.Request.Proto
		fields["RequestURI"] = a.Request.RequestURI
		fields["UpstreamAddress"] = a.Request.URL.Scheme + "://" + a.Request.URL.Host + a.Request.URL.RequestURI()
		fields["UpstreamPath"] = a.Request.URL.Path
		fields["UpstreamURI"] = a.Request.URL.RequestURI()
		fields["UserAgent"] = a.Request.UserAgent()
	}

	// Include response field if it exists
	if a.Response != nil {
		fields["StatusCode"] = a.Response.StatusCode
	}

	return log.WithFields(fields)
}

func (a *AccessLogRecord) WithLatency(latency *analytics.Latency) *AccessLogRecord {
	if latency != nil {
		a.Latency = latency
	}
	return a
}

func (a *AccessLogRecord) WithRequest(req *http.Request) *AccessLogRecord {
	if req != nil {
		a.Request = req
	}
	return a
}

func (a *AccessLogRecord) WithResponse(resp *http.Response) *AccessLogRecord {
	if resp != nil {
		a.Response = resp
	}
	return a
}
