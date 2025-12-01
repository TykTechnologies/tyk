package gateway

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
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
	generateLongString := func(n int) string {
		return strings.Repeat("a", n)
	}

	longURL := "https://example.com/" + generateLongString(300)
	longURLRunes := []rune(longURL)
	expectedTruncatedURL := string(longURLRunes[:255]) + "...(truncated)"

	tests := []struct {
		name       string
		jwksURL    string
		err        error
		wantMsg    string
		wantFields map[string]string
	}{
		{
			name:    "handles excessively large input (dos prevention)",
			jwksURL: "https://example.com/" + generateLongString(5000),
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": expectedTruncatedURL,
			},
		},
		{
			name:    "unreachable host",
			jwksURL: "https://example.com/jwks",
			err: &url.Error{
				Op:  "Get",
				URL: "https://example.com/jwks",
				Err: errors.New("no such host"),
			},
			wantMsg: "JWKS endpoint resolution failed: invalid or unreachable host",
			wantFields: map[string]string{
				"op":  "Get",
				"url": "https://example.com/jwks",
			},
		},
		{
			name:    "sanitizes user credentials",
			jwksURL: "https://user:password@secret.com",
			err:     errors.New("timeout"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": "https://user:xxxxx@secret.com",
			},
		},
		{
			name:    "sanitizes query parameters",
			jwksURL: "https://api.com?access_token=SuperSecret123",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": "https://api.com?access_token=xxxxx",
			},
		},
		{
			name:    "sanitizes url fragments",
			jwksURL: "https://api.com/auth#id_token=SECRET_TOKEN&state=123",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": "https://api.com/auth#id_token=xxxxx&state=123",
			},
		},
		{
			name:    "base64 decode error (structured)",
			jwksURL: "some_base64_source",
			err: &Base64DecodeError{
				Err: errors.New("illegal base64 data"),
			},
			wantMsg: "Failed to decode base64-encoded JWKS source",
			wantFields: map[string]string{
				"source": "some_base64_source",
			},
		},
		{
			name:    "sanitizes multiple sensitive keywords",
			jwksURL: "https://api.com?api_key=123&client_secret=abc&auth_sig=xyz",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				// url.Values.Encode() sorts keys alphabetically
				"url": "https://api.com?api_key=xxxxx&auth_sig=xxxxx&client_secret=xxxxx",
			},
		},
		{
			name:    "sanitizes schemeless credentials",
			jwksURL: "admin:MyP@ssword@127.0.0.1",
			err:     errors.New("timeout"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": "admin:xxxxx@127.0.0.1",
			},
		},
		{
			name:    "utf8 safety and length check",
			jwksURL: "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij©",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				// Expect URL encoded output for special char (%C2%A9 for ©)
				"url": "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij%C2%A9",
			},
		},
		{
			name:    "truncates extremely long urls",
			jwksURL: longURL,
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": expectedTruncatedURL,
			},
		},
		{
			name:    "malformed url with secrets",
			jwksURL: "https://user:secret_pass@host.com/%zz",
			err:     errors.New("fail"),
			wantMsg: "Invalid JWKS retrieved from endpoint",
			wantFields: map[string]string{
				"url": "(malformed input)",
			},
		},
		{
			name:    "sanitizes json syntax errors",
			jwksURL: "https://api.com/jwks",
			err: func() error {
				var v interface{}
				return json.Unmarshal([]byte("invalid-json"), &v)
			}(),
			wantMsg: "Failed to parse JWKS: invalid JSON format",
			wantFields: map[string]string{
				"url": "https://api.com/jwks",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()

			logJWKSFetchError(logger.WithField("ctx", "test"), tt.jwksURL, tt.err)

			if len(hook.Entries) != 1 {
				t.Fatalf("expected 1 log entry, got %d", len(hook.Entries))
			}
			entry := hook.LastEntry()

			if entry.Message != tt.wantMsg {
				t.Errorf("expected message %q, got %q", tt.wantMsg, entry.Message)
			}

			for k, wantV := range tt.wantFields {
				gotV, ok := entry.Data[k]
				if !ok {
					t.Errorf("expected field %q to exist", k)
					continue
				}
				if gotVStr, ok := gotV.(string); ok {
					if gotVStr != wantV {
						t.Errorf("field %q: expected %q, got %q", k, wantV, gotVStr)
					}
				} else {
					t.Errorf("field %q is not a string", k)
				}
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
