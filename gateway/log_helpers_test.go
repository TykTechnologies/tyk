package gateway

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestGetLogEntryForRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testReq := httptest.NewRequest("GET", "http://tyk.io/test", nil)
	testReq.RemoteAddr = "127.0.0.1:80"
	testData := []struct {
		EnableKeyLogging bool
		Key              string
		Data             map[string]interface{}
		Result           *logrus.Entry
	}{
		// enable_key_logging is set, key passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
			}),
		},
		// enable_key_logging is set, key is not passed, no additional data fields
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			}),
		},
		// enable_key_logging is set, key passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    "abc",
				"a":      1,
				"b":      "test",
			}),
		},
		// enable_key_logging is set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: true,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			}),
		},
		// enable_key_logging is not set, key passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"key":    ts.Gw.obfuscateKey("abs"),
			}),
		},
		// enable_key_logging is not set, key is not passed, no additional data field
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             nil,
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
			}),
		},
		// enable_key_logging is not set, key passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "abc",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
				"key":    ts.Gw.obfuscateKey("abc"),
			}),
		},
		// enable_key_logging is not set, key is not passed, additional data fields are passed
		{
			EnableKeyLogging: false,
			Key:              "",
			Data:             map[string]interface{}{"a": 1, "b": "test"},
			Result: logrus.WithFields(logrus.Fields{
				"path":   "/test",
				"origin": "127.0.0.1",
				"a":      1,
				"b":      "test",
			}),
		},
	}
	globalConf := ts.Gw.GetConfig()
	for _, test := range testData {
		globalConf.EnableKeyLogging = test.EnableKeyLogging
		ts.Gw.SetConfig(globalConf)
		logEntry := ts.Gw.getLogEntryForRequest(nil, testReq, test.Key, test.Data)
		if logEntry.Data["path"] != test.Result.Data["path"] {
			t.Error("Expected 'path':", test.Result.Data["path"], "Got:", logEntry.Data["path"])
		}
		if logEntry.Data["origin"] != test.Result.Data["origin"] {
			t.Error("Expected 'origin':", test.Result.Data["origin"], "Got:", logEntry.Data["origin"])
		}
		if logEntry.Data["key"] != test.Result.Data["key"] {
			t.Error("Expected 'key':", test.Result.Data["key"], "Got:", logEntry.Data["key"])
		}
		if test.Data != nil {
			for key, val := range test.Data {
				if logEntry.Data[key] != val {
					t.Error("Expected data key:", key, "with value:", val, "Got:", logEntry.Data[key])
				}
			}
		}
	}
}

func TestGatewayLogJWKError(t *testing.T) {
	// Setup logrus hook to capture logs
	logger, hook := test.NewNullLogger()
	entry := logrus.NewEntry(logger)

	// We only need a minimal Gateway struct since logJWKError doesn't access Gateway fields
	gw := &Gateway{}
	testURL := "https://idp.example.com/jwks"

	tests := []struct {
		name        string
		err         error
		expectedLog string
		shouldLog   bool
	}{
		{
			name:      "No error (nil)",
			err:       nil,
			shouldLog: false,
		},
		{
			name:        "JSON Syntax Error",
			err:         &json.SyntaxError{},
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
			shouldLog:   true,
		},
		{
			name:        "JSON Unmarshal Type Error",
			err:         &json.UnmarshalTypeError{},
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
			shouldLog:   true,
		},
		{
			name:        "String error containing 'invalid character'",
			err:         errors.New("invalid character 'x' looking for beginning of value"),
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
			shouldLog:   true,
		},
		{
			name:        "URL Error type",
			err:         &url.Error{Op: "Get", URL: testURL, Err: errors.New("timeout")},
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
			shouldLog:   true,
		},
		{
			name:        "String error containing 'dial tcp'",
			err:         errors.New("dial tcp: lookup failed"),
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
			shouldLog:   true,
		},
		{
			name:        "String error containing 'no such host'",
			err:         errors.New("Get: no such host"),
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
			shouldLog:   true,
		},
		{
			name:        "String error containing 'connection refused'",
			err:         errors.New("connect: connection refused"),
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
			shouldLog:   true,
		},
		{
			name:        "Generic/Fallback Error",
			err:         errors.New("unknown internal server error"),
			expectedLog: "Failed to fetch or decode JWKs from " + testURL,
			shouldLog:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hook.Reset()

			gw.logJWKError(entry, testURL, tc.err)

			if !tc.shouldLog {
				assert.Empty(t, hook.Entries)
				return
			}

			// Verify log was written
			assert.Len(t, hook.Entries, 1)
			assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)

			// Verify message matches ticket requirements
			assert.Equal(t, tc.expectedLog, hook.LastEntry().Message)

			// Verify the original error is attached
			assert.Equal(t, tc.err, hook.LastEntry().Data["error"])
		})
	}
}
