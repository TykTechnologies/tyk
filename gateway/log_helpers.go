package gateway

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"
)

type Base64DecodeError struct {
	Source string
	Err    error
}

func (e *Base64DecodeError) Error() string {
	return "Failed to decode base64-encoded JWKS source: " + sanitizeSource(e.Source) + " - " + e.Err.Error()
}

// identifies that field value was hidden before output to the log
const logHiddenValue = "<hidden>"

// sanitizeSource truncates the source string and removes control characters
// to prevent leaking secrets or log injection.
func sanitizeSource(source string) string {
	clean := strings.ReplaceAll(source, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")

	const maxLen = 20
	if len(clean) > maxLen {
		return clean[:maxLen] + "...(truncated)"
	}
	return clean
}

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

func logJWKSFetchError(logger *logrus.Entry, sourceOrURL string, err error) {
	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	sanitized := sanitizeSource(sourceOrURL)

	var decodeErr *Base64DecodeError
	if errors.As(err, &decodeErr) {
		logger.WithError(err).Error("JWKS configuration error")
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		logger.WithError(err).Errorf(
			"JWKS endpoint resolution failed: invalid or unreachable host %s",
			sanitized,
		)
		return
	}

	logger.WithError(err).Errorf(
		"Invalid JWKS retrieved from endpoint: %s",
		sanitized,
	)
}
