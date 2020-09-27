package gateway

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/request"

	"github.com/TykTechnologies/tyk/v3/config"
)

// identifies that field value was hidden before output to the log
const logHiddenValue = "<hidden>"

func obfuscateKey(keyName string) string {
	if config.Global().EnableKeyLogging {
		return keyName
	}

	if len(keyName) > 4 {
		return "****" + keyName[len(keyName)-4:]
	}
	return "--"
}

func getLogEntryForRequest(logger *logrus.Entry, r *http.Request, key string, data map[string]interface{}) *logrus.Entry {
	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	// populate http request fields
	fields := logrus.Fields{
		"path":   r.URL.Path,
		"origin": request.RealIP(r),
	}
	// add key to log if configured to do so
	if key != "" {
		fields["key"] = key
		if !config.Global().EnableKeyLogging {
			fields["key"] = obfuscateKey(key)
		}
	}
	// add to log additional fields if any passed
	for key, val := range data {
		fields[key] = val
	}
	return logger.WithFields(fields)
}

func getExplicitLogEntryForRequest(logger *logrus.Entry, path string, IP string, key string, data map[string]interface{}) *logrus.Entry {
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
	return logger.WithFields(fields)
}
