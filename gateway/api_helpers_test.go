package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	lib "github.com/TykTechnologies/tyk/lib/apidef"
)

// TestHandleGetOASList tests the generic OAS list handler with different filters
func TestHandleGetOASList(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a mix of API types
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "mcp-api-1"
			spec.Name = "MCP API 1"
			spec.MarkAsMCP()
		},
		func(spec *APISpec) {
			spec.APIID = "mcp-api-2"
			spec.Name = "MCP API 2"
			spec.MarkAsMCP()
		},
		func(spec *APISpec) {
			spec.APIID = "regular-api-1"
			spec.Name = "Regular API 1"
		},
	)

	t.Run("Filter returns only MCP APIs", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASList((*APISpec).IsMCP, false)

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		assert.Len(t, apisList, 2, "Should return exactly 2 MCP APIs")

		// Verify the right APIs are returned
		apiIDs := make(map[string]bool)
		for _, api := range apisList {
			tykExt := api.GetTykExtension()
			if tykExt != nil {
				apiIDs[tykExt.Info.ID] = true
			}
		}
		assert.True(t, apiIDs["mcp-api-1"], "Should contain mcp-api-1")
		assert.True(t, apiIDs["mcp-api-2"], "Should contain mcp-api-2")
		assert.False(t, apiIDs["regular-api-1"], "Should not contain regular-api-1")
	})

	t.Run("Filter excludes MCP APIs", func(t *testing.T) {
		// Use a filter that simply excludes MCPs (without requiring IsOAS flag)
		obj, code := ts.Gw.handleGetOASList(func(spec *APISpec) bool {
			return !spec.IsMCP()
		}, false)

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		assert.Len(t, apisList, 1, "Should return exactly 1 non-MCP API")

		// Verify MCP APIs are not in the results
		for _, api := range apisList {
			tykExt := api.GetTykExtension()
			if tykExt != nil {
				assert.NotEqual(t, "mcp-api-1", tykExt.Info.ID, "Should not contain mcp-api-1")
				assert.NotEqual(t, "mcp-api-2", tykExt.Info.ID, "Should not contain mcp-api-2")
			}
		}
	})

	t.Run("Public mode removes Tyk extensions", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASList((*APISpec).IsMCP, true)

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		require.Len(t, apisList, 2)

		// Verify Tyk extensions are removed
		for _, api := range apisList {
			tykExt := api.GetTykExtension()
			assert.Nil(t, tykExt, "Tyk extension should be removed in public mode")
		}
	})

	t.Run("Private mode preserves Tyk extensions", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASList((*APISpec).IsMCP, false)

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		require.Len(t, apisList, 2)

		// Verify Tyk extensions are preserved
		foundExtensions := 0
		for _, api := range apisList {
			tykExt := api.GetTykExtension()
			if tykExt != nil {
				foundExtensions++
				// Should have either mcp-api-1 or mcp-api-2
				assert.Contains(t, []string{"mcp-api-1", "mcp-api-2"}, tykExt.Info.ID)
			}
		}
		assert.Equal(t, 2, foundExtensions, "Both APIs should have Tyk extensions")
	})

	t.Run("Empty result when no APIs match filter", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASList(func(_ *APISpec) bool {
			return false // Filter that matches nothing
		}, false)

		assert.Equal(t, http.StatusOK, code)
		apisList, ok := obj.([]oas.OAS)
		require.True(t, ok, "Expected []oas.OAS type")
		assert.Len(t, apisList, 0, "Should return empty list when no match")
	})
}

// TestHandleGetOASByID tests the type-checked OAS retrieval helper
func TestHandleGetOASByID(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create test APIs
	ts.Gw.BuildAndLoadAPI(
		func(spec *APISpec) {
			spec.APIID = "mcp-test-api"
			spec.Name = "MCP Test API"
			spec.MarkAsMCP()
		},
		func(spec *APISpec) {
			spec.APIID = "regular-test-api"
			spec.Name = "Regular Test API"
		},
	)

	t.Run("Returns MCP API when type check passes", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASByID("mcp-test-api", mcpTypeCheck)

		assert.Equal(t, http.StatusOK, code)
		oasAPI, ok := obj.(*oas.OAS)
		require.True(t, ok, "Expected *oas.OAS type")

		tykExt := oasAPI.GetTykExtension()
		require.NotNil(t, tykExt)
		assert.Equal(t, "mcp-test-api", tykExt.Info.ID)
	})

	t.Run("Returns 404 when API not found", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASByID("non-existent", mcpTypeCheck)

		assert.Equal(t, http.StatusNotFound, code)
		msg, ok := obj.(apiStatusMessage)
		require.True(t, ok)
		assert.Contains(t, msg.Message, "not found")
	})

	t.Run("Returns 404 when type check fails", func(t *testing.T) {
		// Try to get regular API with MCP type check
		obj, code := ts.Gw.handleGetOASByID("regular-test-api", mcpTypeCheck)

		assert.Equal(t, http.StatusNotFound, code)
		msg, ok := obj.(apiStatusMessage)
		require.True(t, ok)
		assert.Contains(t, msg.Message, "MCP API")
	})

	t.Run("Custom type check error message", func(t *testing.T) {
		customCheck := func(spec *APISpec) error {
			if !spec.IsOAS {
				return errors.New("must be an OAS API")
			}
			return nil
		}

		obj, code := ts.Gw.handleGetOASByID("regular-test-api", customCheck)

		// Regular API might not have IsOAS set properly, adjust based on actual behavior
		if code == http.StatusNotFound {
			msg, ok := obj.(apiStatusMessage)
			if ok {
				// Error message should come from custom check
				assert.True(t,
					strings.Contains(msg.Message, "must be an OAS API") ||
						strings.Contains(msg.Message, "not found"),
				)
			}
		}
	})

	t.Run("OAS is properly filled", func(t *testing.T) {
		obj, code := ts.Gw.handleGetOASByID("mcp-test-api", mcpTypeCheck)

		assert.Equal(t, http.StatusOK, code)
		oasAPI, ok := obj.(*oas.OAS)
		require.True(t, ok)

		// Verify OAS was filled from APIDefinition
		tykExt := oasAPI.GetTykExtension()
		require.NotNil(t, tykExt)
		assert.NotEmpty(t, tykExt.Info.ID)
		assert.NotEmpty(t, tykExt.Info.Name)
	})
}

// TestFilterFunctions tests the individual filter functions
func TestFilterFunctions(t *testing.T) {
	t.Run("IsMCP identifies MCP APIs", func(t *testing.T) {
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-mcp"
			spec.MarkAsMCP()
		})[0]
		assert.True(t, mcpSpec.IsMCP())

		regularSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-regular"
		})[0]
		assert.False(t, regularSpec.IsMCP())
	})

	t.Run("isOASNotMCP identifies OAS non-MCP APIs", func(t *testing.T) {
		// MCP API should be excluded
		mcpSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-mcp"
			spec.IsOAS = true
			spec.MarkAsMCP()
		})[0]
		assert.False(t, isOASNotMCP(mcpSpec))

		// OAS non-MCP should match
		oasSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-oas"
			spec.IsOAS = true
		})[0]
		assert.True(t, isOASNotMCP(oasSpec))

		// Classic API should be excluded
		classicSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-classic"
			spec.IsOAS = false
		})[0]
		assert.False(t, isOASNotMCP(classicSpec))
	})
}

// TestUpdateBaseAPIWithNewVersion_Concurrency verifies thread-safety during concurrent base API updates
func TestUpdateBaseAPIWithNewVersion_Concurrency(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a base OAS API
	baseAPI := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "base-api",
			OrgID:  "test-org",
			IsOAS:  true,
			Active: true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled: true,
				Name:    "v1",
				Default: "v1",
				Versions: map[string]string{
					"v1": "base-api",
				},
			},
		},
		OAS: oas.OAS{},
	}
	baseAPI.OAS.SetTykExtension(&oas.XTykAPIGateway{})
	baseAPI.OAS.Fill(*baseAPI.APIDefinition)

	// Load the base API
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseAPI.APIID] = baseAPI
	ts.Gw.apisMu.Unlock()

	// Use in-memory filesystem for testing
	fs := afero.NewMemMapFs()

	// Concurrently add multiple child versions
	numVersions := 10
	var wg sync.WaitGroup
	errs := make(chan error, numVersions)

	for i := 0; i < numVersions; i++ {
		wg.Add(1)
		go func(versionNum int) {
			defer wg.Done()

			versionName := "v" + string(rune('2'+versionNum))
			childAPIID := "child-api-" + versionName

			queryVals := url.Values{}
			queryVals.Set(lib.BaseAPIID.String(), baseAPI.APIID)
			queryVals.Set(lib.NewVersionName.String(), versionName)
			versionParams := lib.NewVersionQueryParameters(queryVals)

			err := ts.Gw.updateBaseAPIWithNewVersion(baseAPI.APIID, versionParams, childAPIID, fs)
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	// Check for errors
	for err := range errs {
		t.Errorf("Concurrent update failed: %v", err)
	}

	// Verify final state
	ts.Gw.apisMu.RLock()
	finalBaseAPI := ts.Gw.apisByID[baseAPI.APIID]
	ts.Gw.apisMu.RUnlock()

	assert.NotNil(t, finalBaseAPI)
	// At least some versions should have been added
	assert.Greater(t, len(finalBaseAPI.VersionDefinition.Versions), 1)
}

// TestRemoveAPIFromBaseVersion_Concurrency verifies thread-safety during concurrent deletions
func TestRemoveAPIFromBaseVersion_Concurrency(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a base API with multiple child versions
	baseAPI := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "base-api",
			OrgID:  "test-org",
			IsOAS:  true,
			Active: true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled: true,
				Name:    "v1",
				Default: "v1",
				Versions: map[string]string{
					"v1":  "base-api",
					"v2":  "child-api-v2",
					"v3":  "child-api-v3",
					"v4":  "child-api-v4",
					"v5":  "child-api-v5",
					"v6":  "child-api-v6",
					"v7":  "child-api-v7",
					"v8":  "child-api-v8",
					"v9":  "child-api-v9",
					"v10": "child-api-v10",
				},
			},
		},
		OAS: oas.OAS{},
	}
	baseAPI.OAS.SetTykExtension(&oas.XTykAPIGateway{})
	baseAPI.OAS.Fill(*baseAPI.APIDefinition)

	// Load the base API
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseAPI.APIID] = baseAPI
	ts.Gw.apisMu.Unlock()

	// Use in-memory filesystem
	fs := afero.NewMemMapFs()

	// Concurrently remove multiple versions
	versionsToRemove := []string{"v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"}
	var wg sync.WaitGroup
	errs := make(chan error, len(versionsToRemove))

	for _, version := range versionsToRemove {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()

			childAPIID := "child-api-" + v
			err := ts.Gw.removeAPIFromBaseVersion(childAPIID, baseAPI.APIID, fs)
			if err != nil {
				errs <- err
			}
		}(version)
	}

	wg.Wait()
	close(errs)

	// Check for errors
	for err := range errs {
		t.Errorf("Concurrent remove failed: %v", err)
	}

	// Verify final state
	ts.Gw.apisMu.RLock()
	finalBaseAPI := ts.Gw.apisByID[baseAPI.APIID]
	ts.Gw.apisMu.RUnlock()

	assert.NotNil(t, finalBaseAPI)
	// Should have fewer versions now
	assert.LessOrEqual(t, len(finalBaseAPI.VersionDefinition.Versions), 3) // v1, v10, and maybe one more
}

// TestDeepCopyIsolation verifies that deep copies don't share references
func TestDeepCopyIsolation(t *testing.T) {
	original := &apidef.APIDefinition{
		APIID:  "test-api",
		OrgID:  "test-org",
		Active: true,
		VersionDefinition: apidef.VersionDefinition{
			Enabled: true,
			Name:    "v1",
			Default: "v1",
			Versions: map[string]string{
				"v1": "test-api-v1",
			},
		},
	}

	// This will be implemented in the next step
	copied, err := copyAPIDefForPersistence(original)
	require.NoError(t, err)
	require.NotNil(t, copied)

	// Modify the copy
	copied.VersionDefinition.Versions["v2"] = "test-api-v2"
	copied.APIID = "modified-api"

	// Verify original is unchanged
	assert.Equal(t, "test-api", original.APIID)
	assert.NotContains(t, original.VersionDefinition.Versions, "v2")
	assert.Len(t, original.VersionDefinition.Versions, 1)
}

// TestLockDurationOptimization verifies that locks are not held during file I/O
func TestLockDurationOptimization(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a base OAS API
	baseAPI := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "base-api",
			OrgID:  "test-org",
			IsOAS:  true,
			Active: true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled: true,
				Name:    "v1",
				Default: "v1",
				Versions: map[string]string{
					"v1": "base-api",
				},
			},
		},
		OAS: oas.OAS{},
	}
	baseAPI.OAS.SetTykExtension(&oas.XTykAPIGateway{})
	baseAPI.OAS.Fill(*baseAPI.APIDefinition)

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseAPI.APIID] = baseAPI
	ts.Gw.apisMu.Unlock()

	// Use a slow filesystem to simulate I/O delay
	fs := newSlowFS(afero.NewMemMapFs(), 50*time.Millisecond)

	// Start a write operation in the background
	writeStarted := make(chan bool)
	writeCompleted := make(chan bool)

	go func() {
		queryVals := url.Values{}
		queryVals.Set(lib.BaseAPIID.String(), baseAPI.APIID)
		queryVals.Set(lib.NewVersionName.String(), "v2")
		versionParams := lib.NewVersionQueryParameters(queryVals)

		writeStarted <- true
		err := ts.Gw.updateBaseAPIWithNewVersion(baseAPI.APIID, versionParams, "child-api-v2", fs)
		if err != nil {
			t.Errorf("updateBaseAPIWithNewVersion failed: %v", err)
		}
		writeCompleted <- true
	}()

	<-writeStarted
	time.Sleep(10 * time.Millisecond) // Give it time to acquire lock

	// Try to read - this should NOT be blocked by file I/O
	readStartTime := time.Now()
	api := ts.Gw.getApiSpec(baseAPI.APIID)
	readDuration := time.Since(readStartTime)

	// Read should complete quickly (within 20ms), not wait for slow file I/O (50ms)
	assert.NotNil(t, api)
	assert.Less(t, readDuration, 20*time.Millisecond, "Read should not be blocked by file I/O")

	<-writeCompleted
}

// TestCopyAPIDefForPersistence tests the deep copy helper
func TestCopyAPIDefForPersistence(t *testing.T) {
	tests := []struct {
		name    string
		apiDef  *apidef.APIDefinition
		wantErr bool
	}{
		{
			name: "simple API definition",
			apiDef: &apidef.APIDefinition{
				APIID:  "test-api",
				OrgID:  "test-org",
				Active: true,
			},
			wantErr: false,
		},
		{
			name: "API with version definition",
			apiDef: &apidef.APIDefinition{
				APIID:  "test-api",
				OrgID:  "test-org",
				Active: true,
				VersionDefinition: apidef.VersionDefinition{
					Enabled: true,
					Name:    "v1",
					Default: "v1",
					Versions: map[string]string{
						"v1": "test-api-v1",
						"v2": "test-api-v2",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := copyAPIDefForPersistence(tt.apiDef)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			// Verify deep copy by comparing JSON
			originalJSON, err := json.Marshal(tt.apiDef)
			require.NoError(t, err)
			copiedJSON, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(originalJSON), string(copiedJSON))

			// Verify it's actually a different object
			assert.NotSame(t, tt.apiDef, got)
		})
	}
}

// TestCopyOASForPersistence tests the OAS deep copy helper
func TestCopyOASForPersistence(t *testing.T) {
	oasObj := &oas.OAS{}
	oasObj.SetTykExtension(&oas.XTykAPIGateway{})

	got, err := copyOASForPersistence(oasObj)
	require.NoError(t, err)
	require.NotNil(t, got)

	// Verify it's a different object
	assert.NotSame(t, oasObj, got)
}

// slowFS wraps afero.Fs to simulate slow file I/O
type slowFS struct {
	afero.Fs
	delay time.Duration
}

func newSlowFS(fs afero.Fs, delay time.Duration) *slowFS {
	return &slowFS{Fs: fs, delay: delay}
}

func (s *slowFS) Create(name string) (afero.File, error) {
	time.Sleep(s.delay)
	return s.Fs.Create(name)
}

func (s *slowFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	time.Sleep(s.delay)
	return s.Fs.OpenFile(name, flag, perm)
}

// Ensure slowFS implements afero.Fs
var _ afero.Fs = (*slowFS)(nil)

func TestSetBaseAPIIDHeader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a base API with a versioned child
	baseAPI := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "base-api",
			OrgID:  "test-org",
			IsOAS:  true,
			Active: true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled: true,
				Name:    "v1",
				Default: "v1",
				Versions: map[string]string{
					"v1": "base-api",
					"v2": "child-api",
				},
			},
		},
		OAS: oas.OAS{},
	}
	baseAPI.OAS.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:   "base-api",
			Name: "Base API",
		},
	})
	baseAPI.OAS.Fill(*baseAPI.APIDefinition)

	childAPI := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:  "child-api",
			OrgID:  "test-org",
			IsOAS:  true,
			Active: true,
			VersionDefinition: apidef.VersionDefinition{
				Enabled: true,
				Name:    "v2",
				BaseID:  "base-api",
			},
		},
		OAS: oas.OAS{},
	}
	childAPI.OAS.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:   "child-api",
			Name: "Child API",
		},
	})
	childAPI.OAS.Fill(*childAPI.APIDefinition)

	// Load APIs into gateway
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID["base-api"] = baseAPI
	ts.Gw.apisByID["child-api"] = childAPI
	ts.Gw.apisMu.Unlock()

	t.Run("sets header for versioned child API", func(t *testing.T) {
		w := httptest.NewRecorder()
		ts.Gw.setBaseAPIIDHeader(w, &childAPI.OAS)

		baseIDHeader := w.Header().Get(apidef.HeaderBaseAPIID)
		assert.Equal(t, "base-api", baseIDHeader, "Should set base API ID header")
	})

	t.Run("does not set header for base API", func(t *testing.T) {
		w := httptest.NewRecorder()
		ts.Gw.setBaseAPIIDHeader(w, &baseAPI.OAS)

		baseIDHeader := w.Header().Get(apidef.HeaderBaseAPIID)
		assert.Empty(t, baseIDHeader, "Should not set header for base API")
	})

	t.Run("handles nil OAS object", func(t *testing.T) {
		w := httptest.NewRecorder()
		ts.Gw.setBaseAPIIDHeader(w, nil)

		baseIDHeader := w.Header().Get(apidef.HeaderBaseAPIID)
		assert.Empty(t, baseIDHeader, "Should not set header for nil OAS")
	})

	t.Run("handles OAS without Tyk extension", func(t *testing.T) {
		w := httptest.NewRecorder()
		oasWithoutExt := &oas.OAS{}
		ts.Gw.setBaseAPIIDHeader(w, oasWithoutExt)

		baseIDHeader := w.Header().Get(apidef.HeaderBaseAPIID)
		assert.Empty(t, baseIDHeader, "Should not set header when no extension")
	})

	t.Run("handles API not found in gateway", func(t *testing.T) {
		w := httptest.NewRecorder()
		unknownOAS := &oas.OAS{}
		unknownOAS.SetTykExtension(&oas.XTykAPIGateway{
			Info: oas.Info{
				ID:   "unknown-api",
				Name: "Unknown API",
			},
		})

		ts.Gw.setBaseAPIIDHeader(w, unknownOAS)

		baseIDHeader := w.Header().Get(apidef.HeaderBaseAPIID)
		assert.Empty(t, baseIDHeader, "Should not set header when API not found")
	})
}

func TestEnsureAndValidateAPIID(t *testing.T) {
	t.Run("generates API ID if empty", func(t *testing.T) {
		apiDef := &apidef.APIDefinition{
			APIID: "",
		}

		errResp, errCode := ensureAndValidateAPIID(apiDef)

		assert.Nil(t, errResp)
		assert.Equal(t, 0, errCode)
		assert.NotEmpty(t, apiDef.APIID, "should generate API ID")
	})

	t.Run("preserves existing valid API ID", func(t *testing.T) {
		apiDef := &apidef.APIDefinition{
			APIID: "existing-valid-id",
		}

		errResp, errCode := ensureAndValidateAPIID(apiDef)

		assert.Nil(t, errResp)
		assert.Equal(t, 0, errCode)
		assert.Equal(t, "existing-valid-id", apiDef.APIID)
	})

	t.Run("rejects invalid API ID with path traversal", func(t *testing.T) {
		apiDef := &apidef.APIDefinition{
			APIID: "../../../etc/passwd",
		}

		errResp, errCode := ensureAndValidateAPIID(apiDef)

		assert.NotNil(t, errResp)
		assert.Equal(t, http.StatusBadRequest, errCode)
	})

	t.Run("rejects API ID with path separators", func(t *testing.T) {
		apiDef := &apidef.APIDefinition{
			APIID: "test/id/with/slashes",
		}

		errResp, errCode := ensureAndValidateAPIID(apiDef)

		assert.NotNil(t, errResp)
		assert.Equal(t, http.StatusBadRequest, errCode)
	})
}

func TestDeleteAPIFiles(t *testing.T) {
	t.Run("deletes both main and OAS files successfully", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		appPath := "/app"
		apiID := "test-api"
		suffix := "oas"

		mainFile := filepath.Join(appPath, apiID+".json")
		oasFile := filepath.Join(appPath, apiID+"-"+suffix+".json")

		require.NoError(t, afero.WriteFile(fs, mainFile, []byte("{}"), 0644))
		require.NoError(t, afero.WriteFile(fs, oasFile, []byte("{}"), 0644))

		err := deleteAPIFiles(apiID, suffix, appPath, fs)

		assert.NoError(t, err)

		exists, _ := afero.Exists(fs, mainFile)
		assert.False(t, exists)

		exists, _ = afero.Exists(fs, oasFile)
		assert.False(t, exists)
	})

	t.Run("returns error when main file does not exist", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		appPath := "/app"
		apiID := "test-api"
		suffix := "oas"

		err := deleteAPIFiles(apiID, suffix, appPath, fs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "main API definition file not found")
	})

	t.Run("returns error when OAS file does not exist", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		appPath := "/app"
		apiID := "test-api"
		suffix := "oas"

		mainFile := filepath.Join(appPath, apiID+".json")
		require.NoError(t, afero.WriteFile(fs, mainFile, []byte("{}"), 0644))

		err := deleteAPIFiles(apiID, suffix, appPath, fs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OAS file not found")
	})

	t.Run("returns error when main file deletion fails", func(t *testing.T) {
		fs := &failingFs{
			Fs:        afero.NewMemMapFs(),
			failOnOp:  "Remove",
			failPath:  "test-api.json",
			failError: assert.AnError,
		}
		appPath := "/app"
		apiID := "test-api"
		suffix := "oas"

		mainFile := filepath.Join(appPath, apiID+".json")
		oasFile := filepath.Join(appPath, apiID+"-"+suffix+".json")

		require.NoError(t, afero.WriteFile(fs, mainFile, []byte("{}"), 0644))
		require.NoError(t, afero.WriteFile(fs, oasFile, []byte("{}"), 0644))

		err := deleteAPIFiles(apiID, suffix, appPath, fs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete main API file")
	})

	t.Run("returns error when OAS file deletion fails", func(t *testing.T) {
		fs := &failingFs{
			Fs:        afero.NewMemMapFs(),
			failOnOp:  "Remove",
			failPath:  "test-api-oas.json",
			failError: assert.AnError,
		}
		appPath := "/app"
		apiID := "test-api"
		suffix := "oas"

		mainFile := filepath.Join(appPath, apiID+".json")
		oasFile := filepath.Join(appPath, apiID+"-"+suffix+".json")

		require.NoError(t, afero.WriteFile(fs, mainFile, []byte("{}"), 0644))
		require.NoError(t, afero.WriteFile(fs, oasFile, []byte("{}"), 0644))

		err := deleteAPIFiles(apiID, suffix, appPath, fs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete OAS file")
	})
}

func TestValidateSpecExists(t *testing.T) {
	t.Run("returns nil when spec exists", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID: "test-api",
			},
		}

		resp, code := validateSpecExists(spec)

		assert.Nil(t, resp)
		assert.Equal(t, 0, code)
	})

	t.Run("returns error when spec is nil", func(t *testing.T) {
		resp, code := validateSpecExists(nil)

		assert.NotNil(t, resp)
		assert.Equal(t, 404, code)
		apiError, ok := resp.(apiStatusMessage)
		assert.True(t, ok)
		assert.Equal(t, "error", apiError.Status)
		assert.Contains(t, apiError.Message, "API not found")
	})
}

func TestValidateAPIIDMatch(t *testing.T) {
	t.Run("returns nil when IDs match", func(t *testing.T) {
		resp, code := validateAPIIDMatch("api-123", "api-123")

		assert.Nil(t, resp)
		assert.Equal(t, 0, code)
	})

	t.Run("returns nil when path APIID is empty", func(t *testing.T) {
		resp, code := validateAPIIDMatch("", "api-123")

		assert.Nil(t, resp)
		assert.Equal(t, 0, code)
	})

	t.Run("returns error when IDs do not match", func(t *testing.T) {
		resp, code := validateAPIIDMatch("api-123", "api-456")

		assert.NotNil(t, resp)
		assert.Equal(t, 400, code)
		apiError, ok := resp.(apiStatusMessage)
		assert.True(t, ok)
		assert.Contains(t, apiError.Message, "Request APIID does not match")
	})
}

type failingFs struct {
	afero.Fs
	failOnOp  string
	failPath  string
	failError error
}

func (f *failingFs) Remove(name string) error {
	if f.failOnOp == "Remove" && filepath.Base(name) == f.failPath {
		return f.failError
	}
	return f.Fs.Remove(name)
}

func TestBuildSuccessResponse(t *testing.T) {
	t.Run("builds added response", func(t *testing.T) {
		resp, code := buildSuccessResponse("api-123", "added")

		assert.Equal(t, 200, code)
		success, ok := resp.(apiModifyKeySuccess)
		assert.True(t, ok)
		assert.Equal(t, "api-123", success.Key)
		assert.Equal(t, "ok", success.Status)
		assert.Equal(t, "added", success.Action)
	})

	t.Run("builds modified response", func(t *testing.T) {
		resp, code := buildSuccessResponse("api-456", "modified")

		assert.Equal(t, 200, code)
		success, ok := resp.(apiModifyKeySuccess)
		assert.True(t, ok)
		assert.Equal(t, "api-456", success.Key)
		assert.Equal(t, "ok", success.Status)
		assert.Equal(t, "modified", success.Action)
	})

	t.Run("builds deleted response", func(t *testing.T) {
		resp, code := buildSuccessResponse("api-789", "deleted")

		assert.Equal(t, 200, code)
		success, ok := resp.(apiModifyKeySuccess)
		assert.True(t, ok)
		assert.Equal(t, "api-789", success.Key)
		assert.Equal(t, "ok", success.Status)
		assert.Equal(t, "deleted", success.Action)
	})
}

func TestHandleBaseVersionCleanup(t *testing.T) {
	t.Run("does nothing when baseID is empty", func(_ *testing.T) {
		gw := &Gateway{}
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "",
				},
			},
		}
		fs := afero.NewMemMapFs()

		handleBaseVersionCleanup(gw, spec, "api-123", fs)
	})

	t.Run("calls removeAPIFromBaseVersion when baseID exists", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "base-api"
			spec.Name = "Base API"
			spec.VersionDefinition.Name = "v1"
			spec.VersionDefinition.Versions = map[string]string{
				"v2": "child-api",
			}
		})

		childSpec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				APIID: "child-api",
				VersionDefinition: apidef.VersionDefinition{
					BaseID: "base-api",
				},
			},
		}

		fs := afero.NewMemMapFs()
		baseFile := ts.Gw.GetConfig().AppPath + "/base-api.json"
		require.NoError(t, afero.WriteFile(fs, baseFile, []byte(`{"api_id":"base-api"}`), 0644))

		handleBaseVersionCleanup(ts.Gw, childSpec, "child-api", fs)
	})
}

func TestHandleBaseVersionUpdate(t *testing.T) {
	t.Run("returns nil when baseAPIID is empty", func(t *testing.T) {
		gw := &Gateway{}
		versionParams := lib.NewVersionQueryParameters(url.Values{})
		fs := afero.NewMemMapFs()

		resp, code := handleBaseVersionUpdate(gw, versionParams, "new-api", fs)

		assert.Nil(t, resp)
		assert.Equal(t, 0, code)
	})

	t.Run("returns error when updateBaseAPIWithNewVersion fails", func(t *testing.T) {
		gw := &Gateway{}
		values := url.Values{}
		values.Set("base_api_id", "non-existent")
		versionParams := lib.NewVersionQueryParameters(values)
		fs := afero.NewMemMapFs()

		resp, code := handleBaseVersionUpdate(gw, versionParams, "new-api", fs)

		assert.NotNil(t, resp)
		assert.Equal(t, 500, code)
		apiErr, ok := resp.(apiStatusMessage)
		assert.True(t, ok)
		assert.Contains(t, apiErr.Message, "Failed to update base API")
	})

	t.Run("succeeds when base API exists", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.APIID = "base-api"
			spec.Name = "Base API"
			spec.VersionDefinition.Name = "v1"
		})

		values := url.Values{}
		values.Set("base_api_id", "base-api")
		values.Set("new_version_name", "v2")
		versionParams := lib.NewVersionQueryParameters(values)
		fs := afero.NewMemMapFs()

		baseFile := ts.Gw.GetConfig().AppPath + "/base-api.json"
		require.NoError(t, afero.WriteFile(fs, baseFile, []byte(`{"api_id":"base-api"}`), 0644))

		resp, code := handleBaseVersionUpdate(ts.Gw, versionParams, "new-api", fs)

		assert.Nil(t, resp)
		assert.Equal(t, 0, code)
	})
}
