package httputil

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/request"
)

// AccessLogRecord is a representation of a transaction log in the Gateway
type AccessLogRecord struct {
	APIID            string
	APIKey           string
	ClientRemoteAddr string
	ClientIP         string
	Host             string
	Latency          int64
	Method           string
	OrgID            string
	Protocol         string
	RequestURI       string
	StatusCode       int
	UpstreamAddress  string
	UpstreamLatency  int64
	UpstreamPath     string
	UpstreamURI      string
	UserAgent        string
}

type AccessLogAPISpec struct {
	APIID string
	OrgID string
}

type AccessLog struct {
	*logrus.Logger
}

// Fill will populate the AccessLogRecord with the appropriate data using the APISpec and request
// information
func (a *AccessLogRecord) Fill(latency analytics.Latency, r *http.Request, res *http.Response, s AccessLogAPISpec, token string) error {
	// Validate input parameters are available
	if r == nil {
		return errors.New("HTTP request data cannot be retrieved")
	}
	if res == nil {
		return errors.New("HTTP response data cannot be retrieved")
	}

	a.APIID = s.APIID
	a.APIKey = token
	a.ClientRemoteAddr = r.RemoteAddr
	a.ClientIP = request.RealIP(r)
	a.Host = r.Host
	a.Latency = latency.Total
	a.Method = r.Method
	a.OrgID = s.OrgID
	a.Protocol = r.Proto
	a.RequestURI = r.RequestURI
	a.StatusCode = res.StatusCode
	a.UpstreamAddress = r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI()
	a.UpstreamLatency = latency.Upstream
	a.UpstreamPath = r.URL.Path
	a.UpstreamURI = r.URL.RequestURI()
	a.UserAgent = r.UserAgent()

	return nil
}

// Logger provides a conversion of AccessLogRecord to a logrus.Fields object used for logging
func (a *AccessLogRecord) Logger(log *logrus.Logger) *logrus.Entry {
	fields := logrus.Fields{}

	// Add prefix for logger
	fields["prefix"] = "accessLogs"

	// Iterate through the fields of AccessLogRecord
	v := reflect.ValueOf(a).Elem() // Get the value of the struct
	typeOfA := v.Type()            // Get the type of the struct

	for i := 0; i < v.NumField(); i++ {
		fields[typeOfA.Field(i).Name] = v.Field(i).Interface()
	}

	return log.WithFields(fields)
}

// LogTransaction prints the corresponding transaction log to STDOUT
func (a *AccessLogRecord) LogTransaction(log *logrus.Logger) {
	log.WithFields(a.Logger(log).Data).Info()
}
