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
		name    string
		jwksURL string
		err     error
		wantMsg string
		wantKV  string
	}{
		{
			name:    "unreachable host",
			jwksURL: "https://example.com/jwks",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com/jwks",
				Err: errors.New("no such host"),
			},
			wantMsg: "JWKS endpoint resolution failed: invalid or unreachable host",
			wantKV:  "op=Get url=\"https://example.com/jwks\"",
		},
		{
			name:    "sanitizes user credentials",
			jwksURL: "https://user:password@secret.com",
			err:     errors.New("timeout"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"https://user:xxxxx@secret.com\"",
		},
		{
			name:    "sanitizes query parameters",
			jwksURL: "https://api.com?access_token=SuperSecret123",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"https://api.com?access_token=xxxxx\"",
		},
		{
			name:    "base64 decode error (structured)",
			jwksURL: "12345678901234567890123456789012345678901234567890_OVER_LIMIT",
			err: &Base64DecodeError{
				Err: errors.New("illegal base64 data"),
			},
			wantMsg: "Failed to decode base64-encoded JWKS source",
			wantKV:  "source=\"12345678901234567890123456789012345678901234567890...(truncated)\"",
		},
		{
			name:    "strips control characters",
			jwksURL: "http://bad\nurl\r\tcheck.com",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"http://badurlcheck.com\"",
		},
		{
			name:    "sanitizes multiple sensitive keywords",
			jwksURL: "https://api.com?api_key=123&client_secret=abc&auth_sig=xyz",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"https://api.com?api_key=xxxxx&auth_sig=xxxxx&clien...(truncated)\"",
		},
		{
			name:    "sanitizes schemeless credentials",
			jwksURL: "admin:MyP@ssword@127.0.0.1",
			err:     errors.New("timeout"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"admin:xxxxx@127.0.0.1\"",
		},
		{
			name:    "utf8 safety",
			jwksURL: "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij©", // 51 chars
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij...(truncated)\"",
		},
		{
			name:    "malformed url with secrets",
			jwksURL: "https://user:secret_pass@host.com/%zz",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantKV:  "url=\"(malformed input)\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true, DisableColors: true})
			entry := logrus.NewEntry(logger)

			logJWKSFetchError(entry, tt.jwksURL, tt.err)

			output := buf.String()

			if !strings.Contains(output, tt.wantMsg) {
				t.Errorf("expected log output to contain message %q, got %q", tt.wantMsg, output)
			}

			if !strings.Contains(output, tt.wantKV) {
				t.Errorf("expected log to contain field %q, got %q", tt.wantKV, output)
			}
		})
	}
}

func TestLogJWKSFetchError_NilLogger(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("The code panicked with nil logger: %v", r)
		}
	}()

	logJWKSFetchError(nil, "some-url", errors.New("fail"))
}
