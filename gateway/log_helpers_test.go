package gateway

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
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

func TestLogJWKSFetchError(t *testing.T) {
	tests := []struct {
		name       string
		jwksURL    string
		err        error
		wantOutput string
	}{
		{
			name:    "unreachable host",
			jwksURL: "https://example.com/jwks",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com/jwks",
				Err: errors.New("no such host"),
			},
			wantOutput: "JWKS endpoint resolution failed: invalid or unreachable host https://example.com/jwks",
		},
		{
			name:       "invalid JWKS JSON",
			jwksURL:    "https://example.com/jwks",
			err:        errors.New("failed to parse JWKS JSON"),
			wantOutput: "Invalid JWKS retrieved from endpoint: https://example.com/jwks",
		},
		{
			name:    "base64 decode error",
			jwksURL: "bad_base64_string",
			err: &Base64DecodeError{
				URL: "bad_base64_string",
				Err: errors.New("illegal base64 data"),
			},
			wantOutput: "Failed to decode base64-encoded JWKS URL: bad_base64_string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&buf)
			entry := logrus.NewEntry(logger)

			logJWKSFetchError(entry, tt.jwksURL, tt.err)

			output := buf.String()
			if !strings.Contains(output, tt.wantOutput) {
				t.Errorf("expected log output to contain %q, got %q", tt.wantOutput, output)
			}
		})
	}
}
