package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestGlobalTrafficMirrorMiddleware(t *testing.T) {
	// Create mock destination server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify mirror headers
		if r.Header.Get("X-Tyk-Global-Mirror") != "true" {
			t.Error("Should have global mirror header")
		}
		if r.Header.Get("X-Tyk-Global-Mirror-Source") == "" {
			t.Error("Should have mirror source header")
		}
		if r.Header.Get("X-Tyk-Global-Mirror-Timestamp") == "" {
			t.Error("Should have mirror timestamp header")
		}
		
		// Read body to verify it was cloned correctly
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if string(body) != "test body" {
				t.Error("Body should be cloned correctly")
			}
		}
		
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Create middleware with configuration
	config := map[string]interface{}{
		"destinations": []interface{}{
			map[string]interface{}{
				"url": mockServer.URL,
				"headers": map[string]interface{}{
					"X-Custom-Header": "custom-value",
				},
			},
		},
		"sample_rate": 1.0, // Mirror 100% of requests
		"async":       false,
		"timeout":     5,
		"headers": map[string]interface{}{
			"X-Global-Header": "global-value",
		},
	}

	// Create base middleware
	baseMid := &BaseMiddleware{
		Spec: &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID: "test-api",
			},
		},
	}
	baseMid.Init()

	// Create global base middleware
	globalBase := &GlobalBaseMiddleware{
		BaseMiddleware: baseMid,
		GlobalConfig:   config,
		Phase:         "pre",
		PluginName:    "traffic_mirror",
	}

	// Create global traffic mirror middleware
	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
		configData:           config,
	}
	middleware.Init()

	// Create test request with body
	req := httptest.NewRequest("POST", "http://test.com/path", strings.NewReader("test body"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")

	// Create response writer
	w := httptest.NewRecorder()

	// Process request
	err, code := middleware.ProcessRequest(w, req, nil)

	// Verify no error
	if err != nil {
		t.Errorf("ProcessRequest should not return error: %v", err)
	}

	if code != http.StatusOK {
		t.Errorf("ProcessRequest should return OK status, got %d", code)
	}

	// Give async operations time to complete (if any)
	time.Sleep(100 * time.Millisecond)
}

func TestGlobalTrafficMirrorSampling(t *testing.T) {
	// Create middleware with 0% sampling rate
	config := map[string]interface{}{
		"destinations": []interface{}{
			map[string]interface{}{
				"url": "http://example.com",
			},
		},
		"sample_rate": 0.0, // Mirror 0% of requests
	}

	// Create a minimal base middleware for testing
	baseMid := &BaseMiddleware{}
	baseMid.Init()

	globalBase := &GlobalBaseMiddleware{
		BaseMiddleware: baseMid,
		GlobalConfig:   config,
	}

	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
		configData:           config,
	}

	// Create test request
	req := httptest.NewRequest("GET", "http://test.com/path", nil)
	w := httptest.NewRecorder()

	// Process request
	err, code := middleware.ProcessRequest(w, req, nil)

	// Should still return OK but not mirror anything
	if err != nil {
		t.Errorf("ProcessRequest should not return error: %v", err)
	}

	if code != http.StatusOK {
		t.Errorf("ProcessRequest should return OK status, got %d", code)
	}
}

func TestGlobalTrafficMirrorNoDestinations(t *testing.T) {
	// Create middleware with no destinations
	config := map[string]interface{}{
		"destinations": []interface{}{},
	}

	// Create a minimal base middleware for testing
	baseMid := &BaseMiddleware{}
	baseMid.Init()

	globalBase := &GlobalBaseMiddleware{
		BaseMiddleware: baseMid,
		GlobalConfig:   config,
	}

	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
		configData:           config,
	}

	// Create test request
	req := httptest.NewRequest("GET", "http://test.com/path", nil)
	w := httptest.NewRecorder()

	// Process request
	err, code := middleware.ProcessRequest(w, req, nil)

	// Should return OK without doing anything
	if err != nil {
		t.Errorf("ProcessRequest should not return error: %v", err)
	}

	if code != http.StatusOK {
		t.Errorf("ProcessRequest should return OK status, got %d", code)
	}
}

func TestGlobalTrafficMirrorDestinationParsing(t *testing.T) {
	config := map[string]interface{}{
		"destinations": []interface{}{
			map[string]interface{}{
				"url":     "http://example.com/mirror",
				"timeout": float64(10),
				"headers": map[string]interface{}{
					"X-Mirror-Header": "mirror-value",
				},
			},
			// Invalid destination (no URL)
			map[string]interface{}{
				"timeout": float64(5),
			},
		},
	}

	// Create a minimal base middleware for testing
	baseMid := &BaseMiddleware{}
	baseMid.Init()

	globalBase := &GlobalBaseMiddleware{
		BaseMiddleware: baseMid,
		GlobalConfig:   config,
	}

	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
		configData:           config,
	}

	destinations := middleware.getDestinations()

	// Should only get 1 valid destination
	if len(destinations) != 1 {
		t.Errorf("Expected 1 destination, got %d", len(destinations))
	}

	dest := destinations[0]
	if dest.URL != "http://example.com/mirror" {
		t.Errorf("Expected URL http://example.com/mirror, got %s", dest.URL)
	}

	if dest.Timeout != 10 {
		t.Errorf("Expected timeout 10, got %d", dest.Timeout)
	}

	if dest.Headers["X-Mirror-Header"] != "mirror-value" {
		t.Error("Headers should be parsed correctly")
	}
}

func TestGlobalTrafficMirrorCloneRequest(t *testing.T) {
	globalBase := &GlobalBaseMiddleware{}
	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
	}

	// Create test request with body
	originalBody := "test request body"
	req := httptest.NewRequest("POST", "http://test.com/path?query=value", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")

	// Clone request
	cloned, err := middleware.cloneRequest(req)

	if err != nil {
		t.Errorf("cloneRequest should not return error: %v", err)
	}

	// Verify basic properties
	if cloned.Method != req.Method {
		t.Error("Method should be cloned")
	}

	if cloned.URL.String() != req.URL.String() {
		t.Error("URL should be cloned")
	}

	// Verify headers are deep copied
	if cloned.Header.Get("Content-Type") != "application/json" {
		t.Error("Headers should be cloned")
	}

	// Verify body is cloned and original is preserved
	clonedBody, _ := io.ReadAll(cloned.Body)
	if string(clonedBody) != originalBody {
		t.Error("Body should be cloned correctly")
	}

	// Verify original body is still readable
	originalBodyRead, _ := io.ReadAll(req.Body)
	if string(originalBodyRead) != originalBody {
		t.Error("Original body should be preserved")
	}
}

func TestGlobalTrafficMirrorTimeout(t *testing.T) {
	// Create slow server
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	config := map[string]interface{}{
		"destinations": []interface{}{
			map[string]interface{}{
				"url":     slowServer.URL,
				"timeout": 1, // 1 second timeout
			},
		},
		"timeout": 1,
	}

	// Create a minimal base middleware for testing
	baseMid := &BaseMiddleware{}
	baseMid.Init()

	globalBase := &GlobalBaseMiddleware{
		BaseMiddleware: baseMid,
		GlobalConfig:   config,
	}

	middleware := &GlobalTrafficMirrorMiddleware{
		GlobalBaseMiddleware: globalBase,
		configData:           config,
	}
	middleware.Init()

	// Create test request
	req := httptest.NewRequest("GET", "http://test.com/path", nil)
	w := httptest.NewRecorder()

	// Process request
	start := time.Now()
	err, code := middleware.ProcessRequest(w, req, nil)
	duration := time.Since(start)

	// Should complete quickly due to timeout
	if duration > 3*time.Second {
		t.Error("Request should timeout quickly")
	}

	// Should still return OK
	if err != nil {
		t.Errorf("ProcessRequest should not return error: %v", err)
	}

	if code != http.StatusOK {
		t.Errorf("ProcessRequest should return OK status, got %d", code)
	}
}