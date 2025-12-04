package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

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

func (gw *Gateway) getLogEntryForRequest(logger *logrus.Entry, r *http.Request, key string, data map[string]interface{}) *logrus.Entry {
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
		if !gw.GetConfig().EnableKeyLogging {
			fields["key"] = gw.obfuscateKey(key)
		}
	}
	// add to log additional fields if any passed
	for key, val := range data {
		fields[key] = val
	}
	return logger.WithFields(fields)
}

func (gw *Gateway) getExplicitLogEntryForRequest(logger *logrus.Entry, path string, IP string, key string, data map[string]interface{}) *logrus.Entry {
	// populate http request fields
	fields := logrus.Fields{
		"path":   path,
		"origin": IP,
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
	return logger.WithFields(fields)
}

func (gw *Gateway) logJWKError(logger *logrus.Entry, jwkURL string, err error) {
	if err == nil {
		return
	}

	// invalid content (JSON errors)
	var syntaxErr *json.SyntaxError
	var unmarshalErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &unmarshalErr) || strings.Contains(err.Error(), "invalid character") {
		logger.WithError(err).Errorf("Invalid JWKS retrieved from endpoint: %s", jwkURL)
		return
	}

	// network/URL errors (DNS, TCP, Refused)
	var urlErr *url.Error
	if errors.As(err, &urlErr) || strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "connection refused") {
		logger.WithError(err).Errorf("JWKS endpoint resolution failed: invalid or unreachable host %s", jwkURL)
		return
	}

	logger.WithError(err).Errorf("Failed to fetch or decode JWKs from %s", jwkURL)
}
