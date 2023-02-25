package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/request"
)

// identifies that field value was hidden before output to the log
const logHiddenValue = "<hidden>"

func (gw *Gateway) obfuscateKey(keyName string) string {
	if gw.GetConfig().EnableKeyLogging {
		return keyName
	}

	if len(keyName) > 4 {
		return "****" + keyName[len(keyName)-4:]
	}
	return "--"
}

func (gw *Gateway) getLogEntryForRequest(logger Logger, r *http.Request, key string, data map[string]interface{}) Logger {
	return gw.getExplicitLogEntryForRequest(logger, r.URL.Path, request.RealIP(r), key, data)
}

func (gw *Gateway) getExplicitLogEntryForRequest(logger Logger, requestPath string, requestIP string, key string, data map[string]interface{}) Logger {
	return logger.WithFields(gw.getLogEntryFields(requestPath, requestIP, key, data))
}

func (gw *Gateway) getLogEntryFields(requestPath string, requestIP string, key string, data map[string]interface{}) log.Fields {
	// populate http request fields
	fields := log.Fields{
		"path":   requestPath,
		"origin": requestIP,
	}

	// add key to log if configured to do so
	if key != "" {
		fields["key"] = key
		if !gw.GetConfig().EnableKeyLogging {
			fields["key"] = logHiddenValue
		}
	}

	// add to log additional fields if any passed
	for key, val := range data {
		fields[key] = val
	}

	return fields
}
