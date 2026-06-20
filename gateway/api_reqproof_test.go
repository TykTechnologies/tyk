package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/header"
)

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:determinism:nominal
// MCDC SYS-REQ-139: gateway_control_api_operation_terminal=T => TRUE
// SW-REQ-126:nominal:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIStatusMessages(t *testing.T) {
	testCases := []struct {
		name string
		msg  apiStatusMessage
		want apiStatusMessage
	}{
		{
			name: "success",
			msg:  apiOk("created"),
			want: apiStatusMessage{Status: "ok", Message: "created"},
		},
		{
			name: "error",
			msg:  apiError("failed"),
			want: apiStatusMessage{Status: "error", Message: "failed"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.msg)
		})
	}
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:encoding_safety:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:encoding_safety:nominal
func TestGatewayControlAPIJSONWrite(t *testing.T) {
	t.Run("structured object", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONWrite(recorder, http.StatusAccepted, apiOk("queued"))

		require.Equal(t, http.StatusAccepted, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))

		var msg apiStatusMessage
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &msg))
		assert.Equal(t, apiStatusMessage{Status: "ok", Message: "queued"}, msg)
	})

	t.Run("preencoded bytes", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONWrite(recorder, http.StatusOK, []byte(`{"status":"ok","message":"raw"}`))

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))
		assert.JSONEq(t, `{"status":"ok","message":"raw"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:encoding_safety:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:encoding_safety:nominal
func TestGatewayControlAPIJSONExport(t *testing.T) {
	t.Run("success download", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONExport(recorder, http.StatusOK, map[string]string{"status": "ok"}, "apis.json")

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/octet-stream", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `attachment;filename="apis.json"`, recorder.Header().Get("Content-Disposition"))
		assert.JSONEq(t, `{"status":"ok"}`, recorder.Body.String())
	})

	t.Run("non success delegates to json writer", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		doJSONExport(recorder, http.StatusBadRequest, apiError("bad"), "ignored.json")

		require.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Equal(t, header.ApplicationJSON, recorder.Header().Get(header.ContentType))
		assert.JSONEq(t, `{"status":"error","message":"bad"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:nominal
func TestGatewayControlAPIMethodNotAllowedAndSecureHeaders(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		MethodNotAllowedHandler{}.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/tyk", nil))

		require.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		assert.JSONEq(t, `{"status":"error","message":"Method not supported"}`, recorder.Body.String())
	})

	t.Run("secure and cache headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		called := false
		handler := addSecureAndCacheHeaders(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})

		handler(recorder, httptest.NewRequest(http.MethodGet, "/tyk", nil))

		require.True(t, called)
		require.Equal(t, http.StatusNoContent, recorder.Code)
		assert.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", recorder.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "DENY", recorder.Header().Get("X-Frame-Options"))
		assert.True(t, strings.Contains(recorder.Header().Get("Strict-Transport-Security"), "includeSubDomains"))
		assert.Equal(t, "no-cache, no-store, must-revalidate", recorder.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", recorder.Header().Get("Pragma"))
		assert.Equal(t, "0", recorder.Header().Get("Expires"))
	})
}
