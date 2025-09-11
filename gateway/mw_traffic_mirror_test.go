package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/regexp"
)

func TestTrafficMirrorMiddleware_EnabledForSpec(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Test with no traffic mirror configuration - should be disabled
	spec1 := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			VersionData: struct {
				NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
				DefaultVersion string                        `bson:"default_version" json:"default_version"`
				Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
			}{
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						ExtendedPaths: apidef.ExtendedPathsSet{},
					},
				},
			},
		},
	}

	mw1 := &TrafficMirrorMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec1, Gw: ts.Gw}}
	if mw1.EnabledForSpec() {
		t.Error("Expected middleware to be disabled when no traffic mirror config exists")
	}

	// Test with traffic mirror configuration - should be enabled
	spec2 := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			VersionData: struct {
				NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
				DefaultVersion string                        `bson:"default_version" json:"default_version"`
				Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
			}{
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						ExtendedPaths: apidef.ExtendedPathsSet{
							TrafficMirror: []apidef.TrafficMirrorMeta{
								{
									Path:   "/test",
									Method: "GET",
								},
							},
						},
					},
				},
			},
		},
	}

	mw2 := &TrafficMirrorMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec2, Gw: ts.Gw}}
	if !mw2.EnabledForSpec() {
		t.Error("Expected middleware to be enabled when traffic mirror config exists")
	}
}

func TestTrafficMirrorMiddleware_BasicFunctionality(t *testing.T) {
	// Create a simple test to verify the middleware doesn't crash
	ts := StartTest(nil)
	defer ts.Close()

	// Create a simple mirror server
	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mirrorServer.Close()

	// Create a base middleware for testing
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "test-mirror",
			VersionData: struct {
				NotVersioned   bool                          `bson:"not_versioned" json:"not_versioned"`
				DefaultVersion string                        `bson:"default_version" json:"default_version"`
				Versions       map[string]apidef.VersionInfo `bson:"versions" json:"versions"`
			}{
				DefaultVersion: "v1",
				Versions: map[string]apidef.VersionInfo{
					"v1": {
						Name: "v1",
						ExtendedPaths: apidef.ExtendedPathsSet{
							TrafficMirror: []apidef.TrafficMirrorMeta{
								{
									Disabled:   false,
									Path:       "/test",
									Method:     "GET",
									IgnoreCase: false,
									Async:      false,
									SampleRate: 1.0,
									Destinations: []apidef.TrafficMirrorDestination{
										{
											URL:     mirrorServer.URL,
											Timeout: 5,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Initialize RxPaths for the spec (normally done during API loading)
	// For this simple test, we'll create a URLSpec that always matches
	urlSpec := URLSpec{
		Status:        TrafficMirrored,
		TrafficMirror: spec.VersionData.Versions["v1"].ExtendedPaths.TrafficMirror[0],
	}
	
	// Create a simple regex that matches our test path
	compiledRegex, err := regexp.Compile("^/test$")
	if err != nil {
		t.Fatalf("Failed to compile regex: %v", err)
	}
	urlSpec.spec = compiledRegex
	
	spec.RxPaths = map[string][]URLSpec{
		"v1": {urlSpec},
	}

	baseMw := &BaseMiddleware{Spec: spec, Gw: ts.Gw}
	mw := &TrafficMirrorMiddleware{BaseMiddleware: baseMw}
	mw.Init()

	// Test the ProcessRequest method with a simple request
	req := TestReq(t, "GET", "/test", "")
	
	// Set the version in context (normally done by version middleware)
	ctx := context.WithValue(req.Context(), "version_info", &apidef.VersionInfo{Name: "v1"})
	req = req.WithContext(ctx)

	resp := httptest.NewRecorder()
	
	// Call the middleware
	err, code := mw.ProcessRequest(resp, req, nil)
	
	// Should not return an error and should continue processing
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("Expected status OK, got: %d", code)
	}

	// Note: In a real test environment, we'd need to wait for async operations
	// but this basic test verifies the middleware doesn't crash
}

func TestTrafficMirrorMiddleware_Name(t *testing.T) {
	mw := &TrafficMirrorMiddleware{}
	if mw.Name() != "TrafficMirrorMiddleware" {
		t.Errorf("Expected name 'TrafficMirrorMiddleware', got '%s'", mw.Name())
	}
}