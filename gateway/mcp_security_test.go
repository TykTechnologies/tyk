package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCPSecurity_PathTraversal_Create tests that handleAddMCP rejects path traversal attacks
func TestMCPSecurity_PathTraversal_Create(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	maliciousAPIIDs := []string{
		"../../etc/passwd",
		"../../../sensitive-file",
		"/etc/passwd",
		"C:\\Windows\\System32\\config",
		"valid/../../../etc/passwd",
		".",
		"..",
		"some/path/file",
		"some\\path\\file",
	}

	for _, maliciousID := range maliciousAPIIDs {
		t.Run(fmt.Sprintf("reject_%s", maliciousID), func(t *testing.T) {
			mcpOAS := buildMinimalMCPOAS(t, maliciousID, "Malicious MCP")
			payload, err := json.Marshal(mcpOAS)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(payload))
			fs := afero.NewMemMapFs()

			obj, code := ts.Gw.handleAddMCP(r, fs)

			// Should reject with 400 Bad Request
			assert.Equal(t, http.StatusBadRequest, code, "Expected rejection of malicious API ID: %s", maliciousID)

			resp, ok := obj.(apiStatusMessage)
			if ok {
				assert.Contains(t, resp.Message, "Invalid API ID", "Error message should mention invalid API ID")
			}
		})
	}
}

// TestMCPSecurity_PathTraversal_Update tests that handleUpdateMCP rejects path traversal attacks
func TestMCPSecurity_PathTraversal_Update(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	maliciousAPIIDs := []string{
		"../../etc/passwd",
		"../../../sensitive-file",
		"/absolute/path",
	}

	for _, maliciousID := range maliciousAPIIDs {
		t.Run(fmt.Sprintf("reject_%s", maliciousID), func(t *testing.T) {
			mcpOAS := buildMinimalMCPOAS(t, maliciousID, "Malicious MCP Update")
			payload, err := json.Marshal(mcpOAS)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPut, "/tyk/mcps/"+maliciousID, bytes.NewReader(payload))
			fs := afero.NewMemMapFs()

			obj, code := ts.Gw.handleUpdateMCP(maliciousID, r, fs)

			// Should reject with 400 Bad Request
			assert.Equal(t, http.StatusBadRequest, code, "Expected rejection of malicious API ID: %s", maliciousID)

			resp, ok := obj.(apiStatusMessage)
			if ok {
				assert.Contains(t, resp.Message, "Invalid API ID", "Error message should mention invalid API ID")
			}
		})
	}
}

// TestMCPSecurity_PathTraversal_Delete tests that handleDeleteMCP rejects path traversal attacks
func TestMCPSecurity_PathTraversal_Delete(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	maliciousAPIIDs := []string{
		"../../etc/passwd",
		"../../../sensitive-file",
		"/etc/passwd",
		"..",
		"some/path/file",
	}

	for _, maliciousID := range maliciousAPIIDs {
		t.Run(fmt.Sprintf("reject_%s", maliciousID), func(t *testing.T) {
			fs := afero.NewMemMapFs()
			obj, code := ts.Gw.handleDeleteMCP(maliciousID, fs)

			// Should reject with 400 Bad Request (not 404)
			assert.Equal(t, http.StatusBadRequest, code, "Expected rejection of malicious API ID: %s", maliciousID)

			resp, ok := obj.(apiStatusMessage)
			if ok {
				assert.Contains(t, resp.Message, "Invalid API ID", "Error message should mention invalid API ID")
			}
		})
	}
}

// TestMCPSecurity_PathTraversal_GetByID tests that handleGetMCP validates API ID from URL
func TestMCPSecurity_PathTraversal_GetByID(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	maliciousAPIIDs := []string{
		"../../etc/passwd",
		"/etc/passwd",
	}

	for _, maliciousID := range maliciousAPIIDs {
		t.Run(fmt.Sprintf("reject_%s", maliciousID), func(t *testing.T) {
			obj, code := ts.Gw.handleGetMCP(maliciousID)

			// Should reject with 400 Bad Request
			assert.Equal(t, http.StatusBadRequest, code, "Expected rejection of malicious API ID: %s", maliciousID)

			resp, ok := obj.(apiStatusMessage)
			if ok {
				assert.Contains(t, resp.Message, "Invalid API ID", "Error message should mention invalid API ID")
			}
		})
	}
}

// TestMCPSecurity_ValidAPIIDs tests that valid API IDs still work
func TestMCPSecurity_ValidAPIIDs(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	validAPIIDs := []string{
		"c92bb15331a049f68e6d8a6dafaa8243", // hex UUID
		"test-api-123",                     // alphanumeric with dashes
		"my_api_v2",                        // with underscores
	}

	for _, validID := range validAPIIDs {
		t.Run(fmt.Sprintf("allow_%s", validID), func(t *testing.T) {
			mcpOAS := buildMinimalMCPOAS(t, validID, "Valid MCP")
			payload, err := json.Marshal(mcpOAS)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(payload))
			fs := afero.NewMemMapFs()

			obj, code := ts.Gw.handleAddMCP(r, fs)

			// Should succeed
			assert.Equal(t, http.StatusOK, code, "Valid API ID should be accepted: %s", validID)

			resp, ok := obj.(apiModifyKeySuccess)
			require.True(t, ok)
			assert.Equal(t, "added", resp.Action)
		})
	}
}

// TestMCPSecurity_Handler_Integration tests the actual HTTP handler with path traversal
func TestMCPSecurity_Handler_Integration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Test via actual HTTP handler
	mcpOAS := buildMinimalMCPOAS(t, "../../etc/passwd", "Malicious MCP")
	payload, err := json.Marshal(mcpOAS)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	// Create a router to test the handler
	router := mux.NewRouter()
	router.HandleFunc("/tyk/mcps", ts.Gw.mcpCreateHandler).Methods(http.MethodPost)
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "HTTP handler should reject path traversal")

	var resp apiStatusMessage
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Message, "Invalid API ID")
}
