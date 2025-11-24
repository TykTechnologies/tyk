package gateway

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"
)

type Base64DecodeError struct {
	URL string
	Err error
}

func (e *Base64DecodeError) Error() string {
	return "Failed to decode base64-encoded JWKS URL: " + e.URL + " - " + e.Err.Error()
}

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

func logJWKSFetchError(logger *logrus.Entry, jwksURL string, err error) {
	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	var decodeErr *Base64DecodeError
	if errors.As(err, &decodeErr) {
		logger.WithError(err).Errorf(
			"Failed to decode base64-encoded JWKS URL: %s",
			jwksURL,
		)
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		logger.WithError(err).Errorf(
			"JWKS endpoint resolution failed: invalid or unreachable host %s",
			jwksURL,
		)
		return
	}

	logger.WithError(err).Errorf(
		"Invalid JWKS retrieved from endpoint: %s",
		jwksURL,
	)
}
