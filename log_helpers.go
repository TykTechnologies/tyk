package main

import (
	"net/http"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

// identifies that field value was hidden before output to the log
const (
	logHiddenValue = "<hidden>"
)

func getLogEntryForRequest(r *http.Request, key string, data map[string]interface{}) *logrus.Entry {
	// populate http request fields
	fields := logrus.Fields{
		"path":   r.URL.Path,
		"origin": requestIP(r),
	}
	// add key to log if configured to do so
	if key != "" {
		fields["key"] = key
		if !config.Global.EnableKeyLogging {
			fields["key"] = logHiddenValue
		}
	}
	// add to log additional fields if any passed
	if data != nil && len(data) > 0 {
		for key, val := range data {
			fields[key] = val
		}
	}
	return log.WithFields(fields)
}
