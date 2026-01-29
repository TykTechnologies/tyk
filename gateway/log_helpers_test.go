package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"reflect"
	"syscall"
	"testing"

	"github.com/TykTechnologies/tyk/internal/otel"
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
	logger, hook := test.NewNullLogger()
	entry := logrus.NewEntry(logger)

	gw := &Gateway{}
	testURL := "https://idp.example.com/jwks"

	tests := []struct {
		name        string
		err         error
		expectedLog string
		shouldLog   bool
	}{
		{
			name:      "Nil Error (Should not log)",
			err:       nil,
			shouldLog: false,
		},
		{
			name:        "String-based 'invalid JWK' (go-jose mismatch)",
			err:         errors.New("go-jose: invalid JWK, public keys mismatch"),
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
			shouldLog:   true,
		},
		{
			name:        "JSON Syntax Error",
			err:         &json.SyntaxError{},
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
		},
		{
			name: "JSON Unmarshal Type Error",
			err: &json.UnmarshalTypeError{
				Value: "number",
				Type:  reflect.TypeOf(""),
			},
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
		},
		{
			name:        "Empty Body (io.EOF)",
			err:         io.EOF,
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
		},
		{
			name:        "Typed Base64 Error",
			err:         base64.CorruptInputError(10),
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
		},
		{
			name:        "String-based 'illegal base64' (go-jose fallback)",
			err:         errors.New("illegal base64 data at input byte 0"),
			expectedLog: "Invalid JWKS retrieved from endpoint: " + testURL,
		},

		{
			name:        "URL Error",
			err:         &url.Error{Op: "Get", URL: testURL, Err: errors.New("timeout")},
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
		},
		{
			name:        "Net DNS Error (implements net.Error)",
			err:         &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
		},
		{
			name:        "Net OpError (implements net.Error)",
			err:         &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("timeout")},
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
		},
		{
			name:        "Syscall Connection Refused",
			err:         syscall.ECONNREFUSED,
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
		},
		{
			name:        "Wrapped Connection Refused",
			err:         &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
			expectedLog: "JWKS endpoint resolution failed: invalid or unreachable host " + testURL,
		},
		{
			name:        "Generic Error",
			err:         errors.New("something random"),
			expectedLog: "Failed to fetch or decode JWKs from " + testURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hook.Reset()
			gw.logJWKError(entry, testURL, tc.err)

			if tc.expectedLog == "" {
				assert.Empty(t, hook.Entries)
				return
			}

			if assert.Len(t, hook.Entries, 1) {
				assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
				assert.Equal(t, tc.expectedLog, hook.LastEntry().Message)
			}
		})
	}
}

func TestGetLogEntryForRequest_TraceID(t *testing.T) {
	tests := []struct {
		name          string
		otelEnabled   bool
		hasTraceCtx   bool
		expectTraceID bool
	}{
		{
			name:          "OTel enabled with trace context",
			otelEnabled:   true,
			hasTraceCtx:   true,
			expectTraceID: true,
		},
		{
			name:          "OTel enabled without trace context",
			otelEnabled:   true,
			hasTraceCtx:   false,
			expectTraceID: false,
		},
		{
			name:          "OTel disabled with trace context",
			otelEnabled:   false,
			hasTraceCtx:   true,
			expectTraceID: false,
		},
		{
			name:          "OTel disabled without trace context",
			otelEnabled:   false,
			hasTraceCtx:   false,
			expectTraceID: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			// Setup gateway with OTel config
			globalConf := ts.Gw.GetConfig()
			globalConf.OpenTelemetry.Enabled = tt.otelEnabled
			ts.Gw.SetConfig(globalConf)

			// Create request with or without trace context
			req := httptest.NewRequest("GET", "http://tyk.io/test", nil)
			req.RemoteAddr = "127.0.0.1:80"

			if tt.hasTraceCtx {
				// Initialize OpenTelemetry and create trace context
				globalConf.OpenTelemetry.Exporter = "grpc"
				globalConf.OpenTelemetry.Endpoint = "localhost:4317"
				ts.Gw.SetConfig(globalConf)

				ts.Gw.TracerProvider = otel.InitOpenTelemetry(
					ts.Gw.ctx,
					log,
					&globalConf.OpenTelemetry,
					"test-gateway",
					"1.0.0",
					false,
					"",
					false,
					nil,
				)

				ctx, span := ts.Gw.TracerProvider.Tracer().Start(ts.Gw.ctx, "test-span")
				defer span.End()
				req = req.WithContext(ctx)
			}

			// Get log entry
			entry := ts.Gw.getLogEntryForRequest(nil, req, "", nil)

			// Verify trace_id presence
			_, hasTraceID := entry.Data["trace_id"]
			if hasTraceID != tt.expectTraceID {
				t.Errorf("trace_id presence = %v, want %v", hasTraceID, tt.expectTraceID)
			}

			// Verify trace_id format if present
			if hasTraceID {
				traceID, ok := entry.Data["trace_id"].(string)
				assert.True(t, ok, "trace_id should be a string")
				assert.Len(t, traceID, 32, "trace_id should be 32 characters long")
			}
		})
	}
}

func TestGetLogEntryForRequest_TraceIDConsistency(t *testing.T) {
	// Verify trace_id matches otel.ExtractTraceID()
	ts := StartTest(nil)
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.OpenTelemetry.Enabled = true
	globalConf.OpenTelemetry.Exporter = "grpc"
	globalConf.OpenTelemetry.Endpoint = "localhost:4317"
	ts.Gw.SetConfig(globalConf)

	ts.Gw.TracerProvider = otel.InitOpenTelemetry(
		ts.Gw.ctx,
		log,
		&globalConf.OpenTelemetry,
		"test-gateway",
		"1.0.0",
		false,
		"",
		false,
		nil,
	)

	req := httptest.NewRequest("GET", "http://tyk.io/test", nil)
	req.RemoteAddr = "127.0.0.1:80"

	ctx, span := ts.Gw.TracerProvider.Tracer().Start(ts.Gw.ctx, "test-span")
	defer span.End()
	req = req.WithContext(ctx)

	expectedTraceID := otel.ExtractTraceID(req.Context())

	entry := ts.Gw.getLogEntryForRequest(nil, req, "", nil)

	actualTraceID, ok := entry.Data["trace_id"].(string)
	assert.True(t, ok, "trace_id should be a string")
	assert.Equal(t, expectedTraceID, actualTraceID, "trace_id should match otel.ExtractTraceID()")
}
