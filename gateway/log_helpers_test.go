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

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/otel"
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

func TestGetLogEntryForRequest_TraceAndSpanIDs(t *testing.T) {
	tests := []struct {
		name          string
		otelEnabled   bool
		hasTraceCtx   bool
		expectTraceID bool
		expectSpanID  bool
	}{
		{
			name:          "OTel enabled with trace context",
			otelEnabled:   true,
			hasTraceCtx:   true,
			expectTraceID: true,
			expectSpanID:  true,
		},
		{
			name:          "OTel enabled without trace context",
			otelEnabled:   true,
			hasTraceCtx:   false,
			expectTraceID: false,
			expectSpanID:  false,
		},
		{
			name:          "OTel disabled with trace context",
			otelEnabled:   false,
			hasTraceCtx:   true,
			expectTraceID: false,
			expectSpanID:  false,
		},
		{
			name:          "OTel disabled without trace context",
			otelEnabled:   false,
			hasTraceCtx:   false,
			expectTraceID: false,
			expectSpanID:  false,
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

			// Create request
			req := httptest.NewRequest("GET", "http://tyk.io/test", nil)
			req.RemoteAddr = "127.0.0.1:80"

			// Setup trace context if needed
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

			entry := ts.Gw.getLogEntryForRequest(nil, req, "", nil)

			// Verify trace_id presence
			traceID, hasTraceID := entry.Data["trace_id"]
			assert.Equal(t, tt.expectTraceID, hasTraceID, "trace_id presence mismatch")

			// Verify span_id presence
			spanID, hasSpanID := entry.Data["span_id"]
			assert.Equal(t, tt.expectSpanID, hasSpanID, "span_id presence mismatch")

			// For positive cases, verify format and consistency with extraction functions
			if hasTraceID && hasSpanID {
				// Verify types
				traceIDStr, ok := traceID.(string)
				assert.True(t, ok, "trace_id should be a string")
				spanIDStr, ok := spanID.(string)
				assert.True(t, ok, "span_id should be a string")

				// Verify formats
				assert.Len(t, traceIDStr, 32, "trace_id should be 32 characters long")
				assert.Len(t, spanIDStr, 16, "span_id should be 16 characters long")

				// Verify consistency with extraction functions
				expectedTraceID := otel.ExtractTraceID(req.Context())
				assert.Equal(t, expectedTraceID, traceIDStr, "trace_id should match otel.ExtractTraceID()")

				extractedTraceID, extractedSpanID := otel.ExtractTraceAndSpanID(req.Context())
				assert.Equal(t, extractedTraceID, traceIDStr, "trace_id should match otel.ExtractTraceAndSpanID()")
				assert.Equal(t, extractedSpanID, spanIDStr, "span_id should match otel.ExtractTraceAndSpanID()")

				// Verify IDs match the span context
				span := otel.SpanFromContext(req.Context())
				assert.Equal(t, span.SpanContext().TraceID().String(), traceIDStr, "trace_id should match span context")
				assert.Equal(t, span.SpanContext().SpanID().String(), spanIDStr, "span_id should match span context")
			}
		})
	}
}
