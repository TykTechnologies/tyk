package main

import (
	"net/http"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk/config"
)

// identifies that field value was hidden before output to the log
const logHiddenValue = "<hidden>"

func getLogEntryForRequest(r *http.Request, key string, data map[string]interface{}) *logrus.Entry {
	// populate http request fields
	fields := logrus.Fields{
		"path":   r.URL.Path,
		"origin": request.RealIP(r),
	}
	// add key to log if configured to do so
	if key != "" {
		fields["key"] = key
		if !config.Global().EnableKeyLogging {
			fields["key"] = logHiddenValue
		}
	}
	// add to log additional fields if any passed
	for key, val := range data {
		fields[key] = val
	}
	return log.WithFields(fields)
}

func getExplicitLogEntryForRequest(path string, IP string, key string, data map[string]interface{}) *logrus.Entry {
	// populate http request fields
	fields := logrus.Fields{
		"path":   path,
		"origin": IP,
	}
	// add key to log if configured to do so
	if key != "" {
		fields["key"] = key
		if !config.Global().EnableKeyLogging {
			fields["key"] = logHiddenValue
		}
	}
	// add to log additional fields if any passed
	for key, val := range data {
		fields[key] = val
	}
	return log.WithFields(fields)
}
