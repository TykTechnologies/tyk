package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// TestMCPVersioning_CreateStandalone tests creating an MCP API without versioning
func TestMCPVersioning_CreateStandalone(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	mcpOAS := buildMinimalMCPOAS(t, "", "Standalone MCP")
	payload, err := json.Marshal(mcpOAS)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(payload))
	fs := afero.NewMemMapFs()

	obj, code := ts.Gw.handleAddMCP(r, fs)

	assert.Equal(t, http.StatusOK, code)
	resp, ok := obj.(apiModifyKeySuccess)
	require.True(t, ok)
	assert.Equal(t, "added", resp.Action)
	assert.NotEmpty(t, resp.Key)

	// Verify files were written to mock FS
	defPath := fmt.Sprintf("%s/%s.json", ts.Gw.GetConfig().AppPath, resp.Key)
	exists, err := afero.Exists(fs, defPath)
	require.NoError(t, err)
	assert.True(t, exists, "API definition file should exist")

	mcpPath := fmt.Sprintf("%s/%s-mcp.json", ts.Gw.GetConfig().AppPath, resp.Key)
	exists, err = afero.Exists(fs, mcpPath)
	require.NoError(t, err)
	assert.True(t, exists, "MCP OAS file should exist")
}

// TestMCPVersioning_CreateAsVersion tests creating an MCP API as a version of existing base
func TestMCPVersioning_CreateAsVersion(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base MCP API first using handler and mock FS
	fs := afero.NewMemMapFs()
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	basePayload, err := json.Marshal(baseOAS)
	require.NoError(t, err)

	baseReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(basePayload))
	baseObj, baseCode := ts.Gw.handleAddMCP(baseReq, fs)
	require.Equal(t, http.StatusOK, baseCode)

	// Manually register base API in memory so getApiSpec can find it
	baseResp, ok := baseObj.(apiModifyKeySuccess)
	require.True(t, ok)

	baseSpec := &APISpec{}
	baseSpec.APIDefinition = &apidef.APIDefinition{}
	baseSpec.APIID = baseResp.Key
	baseSpec.Name = "Base MCP"
	baseSpec.MarkAsMCP()
	baseSpec.IsOAS = true
	baseSpec.OAS = *baseOAS
	baseSpec.OAS.ExtractTo(baseSpec.APIDefinition)
	baseSpec.VersionDefinition.Name = "v1"
	baseSpec.VersionDefinition.Enabled = true
	baseSpec.VersionDefinition.Default = "v1"
	baseSpec.VersionDefinition.Versions = map[string]string{}

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseSpec.APIID] = baseSpec
	ts.Gw.apisMu.Unlock()

	// Create child version v2
	childOAS := buildMinimalMCPOAS(t, "", "MCP v2")
	payload, err := json.Marshal(childOAS)
	require.NoError(t, err)

	reqURL, err := url.Parse(fmt.Sprintf("/tyk/mcps?base_api_id=%s&new_version_name=v2", baseResp.Key))
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(payload))
	r.URL = reqURL

	obj, code := ts.Gw.handleAddMCP(r, fs)

	assert.Equal(t, http.StatusOK, code)
	resp, ok := obj.(apiModifyKeySuccess)
	require.True(t, ok)
	assert.Equal(t, "added", resp.Action)

	// Verify base API file was updated with new version
	baseDefPath := fmt.Sprintf("%s/%s-mcp.json", ts.Gw.GetConfig().AppPath, baseResp.Key)
	exists, err := afero.Exists(fs, baseDefPath)
	require.NoError(t, err)
	assert.True(t, exists, "Base API OAS file should be updated")

	// Read and verify base API has the new version registered
	baseData, err := afero.ReadFile(fs, baseDefPath)
	require.NoError(t, err)

	var updatedBaseOAS oas.OAS
	require.NoError(t, json.Unmarshal(baseData, &updatedBaseOAS))

	var baseDef apidef.APIDefinition
	updatedBaseOAS.ExtractTo(&baseDef)

	assert.Contains(t, baseDef.VersionDefinition.Versions, "v2")
	assert.Equal(t, resp.Key, baseDef.VersionDefinition.Versions["v2"])
	assert.Equal(t, "v1", baseDef.VersionDefinition.Default) // Default should remain v1
}

// TestMCPVersioning_CreateAsVersionAndSetDefault tests creating version and setting it as default
func TestMCPVersioning_CreateAsVersionAndSetDefault(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base MCP API using handler
	fs := afero.NewMemMapFs()
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	basePayload, err := json.Marshal(baseOAS)
	require.NoError(t, err)

	baseReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(basePayload))
	baseObj, baseCode := ts.Gw.handleAddMCP(baseReq, fs)
	require.Equal(t, http.StatusOK, baseCode)

	baseResp, ok := baseObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Manually register base API in memory
	baseSpec := &APISpec{}
	baseSpec.APIDefinition = &apidef.APIDefinition{}
	baseSpec.APIID = baseResp.Key
	baseSpec.Name = "Base MCP"
	baseSpec.MarkAsMCP()
	baseSpec.IsOAS = true
	baseSpec.OAS = *baseOAS
	baseSpec.OAS.ExtractTo(baseSpec.APIDefinition)
	baseSpec.VersionDefinition.Name = "v1"
	baseSpec.VersionDefinition.Enabled = true
	baseSpec.VersionDefinition.Default = "v1"
	baseSpec.VersionDefinition.Versions = map[string]string{}

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseSpec.APIID] = baseSpec
	ts.Gw.apisMu.Unlock()

	// Create v2 and set as default
	childOAS := buildMinimalMCPOAS(t, "", "MCP v2")
	payload, err := json.Marshal(childOAS)
	require.NoError(t, err)

	reqURL, err := url.Parse(fmt.Sprintf("/tyk/mcps?base_api_id=%s&new_version_name=v2&set_default=true", baseResp.Key))
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(payload))
	r.URL = reqURL

	_, code := ts.Gw.handleAddMCP(r, fs)

	assert.Equal(t, http.StatusOK, code)

	// Reload base spec from memory to see updates
	updatedBaseSpec := ts.Gw.getApiSpec(baseResp.Key)
	require.NotNil(t, updatedBaseSpec)
	assert.Equal(t, "v2", updatedBaseSpec.VersionDefinition.Default)
}

// TestMCPVersioning_CreateWithInvalidBaseID tests failure when base API doesn't exist
func TestMCPVersioning_CreateWithInvalidBaseID(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	mcpOAS := buildMinimalMCPOAS(t, "", "Test MCP")
	payload, err := json.Marshal(mcpOAS)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/tyk/mcps?base_api_id=nonexistent&new_version_name=v2", bytes.NewReader(payload))
	w := httptest.NewRecorder()

	ts.Gw.mcpCreateHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp apiStatusMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.Message, "Base API")
}

// TestMCPVersioning_CreateWithoutVersionName tests failure when version name missing
func TestMCPVersioning_CreateWithoutVersionName(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base API
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "base-mcp"
		spec.Name = "Base MCP"
		spec.MarkAsMCP()
		spec.IsOAS = true
		spec.OAS = *baseOAS
		spec.VersionDefinition.Name = "v1"
		spec.VersionDefinition.Enabled = true
	})

	mcpOAS := buildMinimalMCPOAS(t, "", "Test MCP")
	payload, err := json.Marshal(mcpOAS)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/tyk/mcps?base_api_id=base-mcp", bytes.NewReader(payload))
	w := httptest.NewRecorder()

	ts.Gw.mcpCreateHandler(w, r)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// TestMCPVersioning_UpdateStandalone tests updating a standalone MCP API
func TestMCPVersioning_UpdateStandalone(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create standalone MCP using handler
	fs := afero.NewMemMapFs()
	originalOAS := buildMinimalMCPOAS(t, "standalone-mcp", "Original MCP")
	createPayload, err := json.Marshal(originalOAS)
	require.NoError(t, err)

	createReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(createPayload))
	createObj, createCode := ts.Gw.handleAddMCP(createReq, fs)
	require.Equal(t, http.StatusOK, createCode)

	createResp, ok := createObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Manually register API in memory
	spec := &APISpec{}
	spec.APIDefinition = &apidef.APIDefinition{}
	spec.APIID = createResp.Key
	spec.Name = "Original MCP"
	spec.MarkAsMCP()
	spec.IsOAS = true
	spec.OAS = *originalOAS
	spec.OAS.ExtractTo(spec.APIDefinition)

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[spec.APIID] = spec
	ts.Gw.apisMu.Unlock()

	// Update it
	updatedOAS := buildMinimalMCPOAS(t, createResp.Key, "Updated MCP")
	payload, err := json.Marshal(updatedOAS)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tyk/mcps/%s", createResp.Key), bytes.NewReader(payload))
	r = mux.SetURLVars(r, map[string]string{"apiID": createResp.Key})

	obj, code := ts.Gw.handleUpdateMCP(createResp.Key, r, fs)

	assert.Equal(t, http.StatusOK, code)
	resp, ok := obj.(apiModifyKeySuccess)
	require.True(t, ok)
	assert.Equal(t, "modified", resp.Action)
}

// TestMCPVersioning_UpdateVersionedChild tests updating a versioned MCP maintains BaseID
func TestMCPVersioning_UpdateVersionedChild(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base MCP API
	fs := afero.NewMemMapFs()
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	basePayload, err := json.Marshal(baseOAS)
	require.NoError(t, err)

	baseReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(basePayload))
	baseObj, baseCode := ts.Gw.handleAddMCP(baseReq, fs)
	require.Equal(t, http.StatusOK, baseCode)

	baseResp, ok := baseObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Register base API in memory
	baseSpec := &APISpec{}
	baseSpec.APIDefinition = &apidef.APIDefinition{}
	baseSpec.APIID = baseResp.Key
	baseSpec.Name = "Base MCP"
	baseSpec.MarkAsMCP()
	baseSpec.IsOAS = true
	baseSpec.OAS = *baseOAS
	baseSpec.OAS.ExtractTo(baseSpec.APIDefinition)
	baseSpec.VersionDefinition.Name = "v1"
	baseSpec.VersionDefinition.Enabled = true
	baseSpec.VersionDefinition.Default = "v1"
	baseSpec.VersionDefinition.Versions = map[string]string{}

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseSpec.APIID] = baseSpec
	ts.Gw.apisMu.Unlock()

	// Create child version
	childOAS := buildMinimalMCPOAS(t, "", "Child MCP")
	childPayload, err := json.Marshal(childOAS)
	require.NoError(t, err)

	childURL, err := url.Parse(fmt.Sprintf("/tyk/mcps?base_api_id=%s&new_version_name=v2", baseResp.Key))
	require.NoError(t, err)
	childReq := httptest.NewRequest(http.MethodPost, childURL.String(), bytes.NewReader(childPayload))
	childReq.URL = childURL

	childObj, childCode := ts.Gw.handleAddMCP(childReq, fs)
	require.Equal(t, http.StatusOK, childCode)

	childResp, ok := childObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Register child in memory with BaseID
	childSpec := &APISpec{}
	childSpec.APIDefinition = &apidef.APIDefinition{}
	childSpec.Name = "Child MCP"
	childSpec.MarkAsMCP()
	childSpec.IsOAS = true
	childSpec.OAS = *childOAS
	childSpec.OAS.ExtractTo(childSpec.APIDefinition)
	childSpec.APIID = childResp.Key
	childSpec.VersionDefinition.BaseID = baseResp.Key

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[childSpec.APIID] = childSpec
	// Update base API's version map
	ts.Gw.apisByID[baseSpec.APIID].VersionDefinition.Versions["v2"] = childResp.Key
	ts.Gw.apisMu.Unlock()

	// Update child
	updatedChildOAS := buildMinimalMCPOAS(t, childResp.Key, "Updated Child MCP")
	payload, err := json.Marshal(updatedChildOAS)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tyk/mcps/%s", childResp.Key), bytes.NewReader(payload))
	r = mux.SetURLVars(r, map[string]string{"apiID": childResp.Key})

	_, code := ts.Gw.handleUpdateMCP(childResp.Key, r, fs)

	assert.Equal(t, http.StatusOK, code)

	// Verify BaseID is preserved
	updatedChildSpec := ts.Gw.getApiSpec(childResp.Key)
	require.NotNil(t, updatedChildSpec)
	assert.Equal(t, baseResp.Key, updatedChildSpec.VersionDefinition.BaseID)
}

// TestMCPVersioning_GetReturnsBaseIDHeader tests GET returns X-Tyk-Base-API-ID header
func TestMCPVersioning_GetReturnsBaseIDHeader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base MCP API
	fs := afero.NewMemMapFs()
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	basePayload, err := json.Marshal(baseOAS)
	require.NoError(t, err)

	baseReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(basePayload))
	baseObj, baseCode := ts.Gw.handleAddMCP(baseReq, fs)
	require.Equal(t, http.StatusOK, baseCode)

	baseResp, ok := baseObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Register base API in memory
	baseSpec := &APISpec{}
	baseSpec.APIDefinition = &apidef.APIDefinition{}
	baseSpec.APIID = baseResp.Key
	baseSpec.Name = "Base MCP"
	baseSpec.MarkAsMCP()
	baseSpec.IsOAS = true
	baseSpec.OAS = *baseOAS
	baseSpec.OAS.ExtractTo(baseSpec.APIDefinition)
	baseSpec.VersionDefinition.Name = "v1"
	baseSpec.VersionDefinition.Enabled = true
	baseSpec.VersionDefinition.Default = "v1"
	baseSpec.VersionDefinition.Versions = map[string]string{}

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseSpec.APIID] = baseSpec
	ts.Gw.apisMu.Unlock()

	// Create child version
	childOAS := buildMinimalMCPOAS(t, "", "Child MCP")
	childPayload, err := json.Marshal(childOAS)
	require.NoError(t, err)

	childURL, err := url.Parse(fmt.Sprintf("/tyk/mcps?base_api_id=%s&new_version_name=v2", baseResp.Key))
	require.NoError(t, err)
	childReq := httptest.NewRequest(http.MethodPost, childURL.String(), bytes.NewReader(childPayload))
	childReq.URL = childURL

	childObj, childCode := ts.Gw.handleAddMCP(childReq, fs)
	require.Equal(t, http.StatusOK, childCode)

	childResp, ok := childObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Register child in memory with BaseID
	childSpec := &APISpec{}
	childSpec.APIDefinition = &apidef.APIDefinition{}
	childSpec.Name = "Child MCP"
	childSpec.MarkAsMCP()
	childSpec.IsOAS = true
	childSpec.OAS = *childOAS
	childSpec.OAS.ExtractTo(childSpec.APIDefinition)
	childSpec.APIID = childResp.Key
	childSpec.VersionDefinition.BaseID = baseResp.Key

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[childSpec.APIID] = childSpec
	ts.Gw.apisMu.Unlock()

	// Test GET returns BaseID header
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tyk/mcps/%s", childResp.Key), nil)
	r = mux.SetURLVars(r, map[string]string{"apiID": childResp.Key})
	w := httptest.NewRecorder()

	ts.Gw.mcpGetHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, baseResp.Key, w.Header().Get(apidef.HeaderBaseAPIID))
}

// buildMinimalMCPOAS creates a minimal valid MCP OAS for testing
func buildMinimalMCPOAS(t *testing.T, apiID, name string) *oas.OAS {
	t.Helper()

	oasObj := &oas.OAS{}
	oasObj.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:   apiID,
			Name: name,
			State: oas.State{
				Active: true,
			},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: fmt.Sprintf("/%s/", name),
				Strip: true,
			},
		},
		Upstream: oas.Upstream{
			URL: "http://example.com",
		},
	})

	return oasObj
}

// TestMCPVersioning_ConcurrentVersionCreation tests race-free version creation
// This test verifies that creating multiple versions concurrently doesn't cause
// data races when modifying the base API specification.
func TestMCPVersioning_ConcurrentVersionCreation(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create base MCP API
	fs := afero.NewMemMapFs()
	baseOAS := buildMinimalMCPOAS(t, "base-mcp", "Base MCP")
	basePayload, err := json.Marshal(baseOAS)
	require.NoError(t, err)

	baseReq := httptest.NewRequest(http.MethodPost, "/tyk/mcps", bytes.NewReader(basePayload))
	baseObj, baseCode := ts.Gw.handleAddMCP(baseReq, fs)
	require.Equal(t, http.StatusOK, baseCode)

	baseResp, ok := baseObj.(apiModifyKeySuccess)
	require.True(t, ok)

	// Register base API in memory
	baseSpec := &APISpec{}
	baseSpec.APIDefinition = &apidef.APIDefinition{}
	baseSpec.APIID = baseResp.Key
	baseSpec.Name = "Base MCP"
	baseSpec.MarkAsMCP()
	baseSpec.IsOAS = true
	baseSpec.OAS = *baseOAS
	baseSpec.OAS.ExtractTo(baseSpec.APIDefinition)
	baseSpec.VersionDefinition.Name = "v1"
	baseSpec.VersionDefinition.Enabled = true
	baseSpec.VersionDefinition.Default = "v1"
	baseSpec.VersionDefinition.Versions = map[string]string{}

	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID[baseSpec.APIID] = baseSpec
	ts.Gw.apisMu.Unlock()

	// Create multiple versions concurrently
	// This should not trigger data races with -race flag
	const numVersions = 5
	results := make(chan error, numVersions)

	for i := 0; i < numVersions; i++ {
		go func(versionNum int) {
			versionName := fmt.Sprintf("v%d", versionNum+2)
			childOAS := buildMinimalMCPOAS(t, "", fmt.Sprintf("MCP %s", versionName))
			payload, err := json.Marshal(childOAS)
			if err != nil {
				results <- err
				return
			}

			reqURL, err := url.Parse(fmt.Sprintf("/tyk/mcps?base_api_id=%s&new_version_name=%s", baseResp.Key, versionName))
			if err != nil {
				results <- err
				return
			}

			r := httptest.NewRequest(http.MethodPost, reqURL.String(), bytes.NewReader(payload))
			r.URL = reqURL

			_, code := ts.Gw.handleAddMCP(r, fs)
			if code != http.StatusOK {
				results <- fmt.Errorf("expected status 200, got %d", code)
				return
			}

			results <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numVersions; i++ {
		err := <-results
		assert.NoError(t, err, "Version creation should succeed")
	}
}
