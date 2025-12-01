package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"
)

// sensitiveKeys defines which parameters to redact.
var sensitiveKeys = map[string]struct{}{
	"token":         {},
	"access_token":  {},
	"id_token":      {},
	"secret":        {},
	"client_secret": {},
	"key":           {},
	"api_key":       {},
	"auth":          {},
	"auth_sig":      {},
	"sig":           {},
	"password":      {},
}

type base64DecodeError struct {
	Err error
}

func (e *base64DecodeError) Error() string {
	// Simple return. The logging helper handles the context and sanitization.
	return "failed to decode base64-encoded JWKS source: " + e.Err.Error()
}

// identifies that field value was hidden before output to the log
const logHiddenValue = "<hidden>"

// sanitizeSource truncates the source string, removes control characters,
// and redacts credentials to prevent leaking secrets.
func sanitizeSource(source string) string {
	const maxInputLen = 4096
	if len(source) > maxInputLen {
		source = source[:maxInputLen]
	}

	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, source)

	parseTarget := clean
	addedScheme := false
	if !strings.Contains(clean, "://") {
		parseTarget = "http://" + clean
		addedScheme = true
	}

	u, err := url.Parse(parseTarget)
	if err != nil {
		return "(malformed input)"
	}

	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}

	redactValues := func(vals url.Values) bool {
		changed := false
		for param := range vals {
			for sensitive := range sensitiveKeys {
				if strings.EqualFold(param, sensitive) {
					vals.Set(param, "xxxxx")
					changed = true
					break
				}
			}
		}
		return changed
	}

	q := u.Query()
	if redactValues(q) {
		u.RawQuery = q.Encode()
	}

	if u.Fragment != "" {
		if !strings.Contains(u.Fragment, "=") {
			u.Fragment = "xxxxx"
		} else {
			fragVals, err := url.ParseQuery(u.Fragment)
			if err != nil {
				u.Fragment = "xxxxx"
			} else if len(fragVals) > 0 {
				if redactValues(fragVals) {
					u.Fragment = fragVals.Encode()
				}
			}
		}
	}

	clean = u.String()

	if addedScheme {
		clean = strings.TrimPrefix(clean, "http://")
	}

	const maxLen = 255
	runes := []rune(clean)
	if len(runes) > maxLen {
		return string(runes[:maxLen]) + "...(truncated)"
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

	var decodeErr *base64DecodeError
	if errors.As(err, &decodeErr) {
		logger.WithField("source", sanitized).
			WithError(decodeErr.Err).
			Error("Failed to decode base64-encoded JWKS source")
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		logger.WithFields(logrus.Fields{
			"url": sanitized,
			"op":  urlErr.Op,
		}).
			WithError(urlErr.Err).
			Error("JWKS endpoint resolution failed: invalid or unreachable host")
		return
	}

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		logger.WithField("url", sanitized).
			Error("Failed to parse JWKS: invalid JSON format")
		return
	}

	logger.WithError(err).
		WithField("url", sanitized).
		Error("Invalid JWKS retrieved from endpoint")
}
