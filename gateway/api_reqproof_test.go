package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/pkg/identifier"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
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

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:error_handling:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:error_handling:nominal
func TestGatewayControlAPIAllowMethods(t *testing.T) {
	t.Run("allowed method invokes handler", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		called := false
		handler := allowMethods(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusAccepted)
		}, http.MethodGet, http.MethodPost)

		handler(recorder, httptest.NewRequest(http.MethodPost, "/tyk", nil))

		require.True(t, called)
		assert.Equal(t, http.StatusAccepted, recorder.Code)
	})

	t.Run("unsupported method returns json error", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		handler := allowMethods(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}, http.MethodGet)

		handler(recorder, httptest.NewRequest(http.MethodDelete, "/tyk", nil))

		require.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		assert.JSONEq(t, `{"status":"error","message":"Method not supported"}`, recorder.Body.String())
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIOrgLookupHelpers(t *testing.T) {
	specs := BuildAPI(
		func(spec *APISpec) {
			spec.APIID = "api-a"
			spec.OrgID = "org-a"
		},
		func(spec *APISpec) {
			spec.APIID = "api-b"
			spec.OrgID = "org-b"
		},
		func(spec *APISpec) {
			spec.APIID = "api-c"
			spec.OrgID = "org-a"
		},
	)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"api-a": specs[0],
			"api-b": specs[1],
			"api-c": specs[2],
		},
	}

	t.Run("get spec for matching org", func(t *testing.T) {
		spec := gw.getSpecForOrg("org-b")

		require.NotNil(t, spec)
		assert.Equal(t, "api-b", spec.APIID)
	})

	t.Run("get spec falls back when org missing", func(t *testing.T) {
		spec := gw.getSpecForOrg("missing-org")

		require.NotNil(t, spec)
		assert.Contains(t, []string{"api-a", "api-b", "api-c"}, spec.APIID)
	})

	t.Run("get spec returns nil with no apis", func(t *testing.T) {
		empty := &Gateway{apisByID: map[string]*APISpec{}}

		assert.Nil(t, empty.getSpecForOrg("org-a"))
	})

	t.Run("list api ids for org", func(t *testing.T) {
		ids := gw.getApisIdsForOrg("org-a")

		assert.ElementsMatch(t, []string{"api-a", "api-c"}, ids)
	})

	t.Run("list all api ids", func(t *testing.T) {
		ids := gw.getApisIdsForOrg("")

		assert.ElementsMatch(t, []string{"api-a", "api-b", "api-c"}, ids)
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIInventoryListFilters(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	classic := BuildAPI(func(spec *APISpec) {
		spec.APIID = "classic-api"
		spec.Name = "Classic API"
	})[0]
	mcp := BuildAPI(func(spec *APISpec) {
		spec.APIID = "mcp-api"
		spec.Name = "MCP API"
		spec.MarkAsMCP()
	})[0]
	oasSpec := BuildOASAPI(func(oasDef *oas.OAS) {
		tykExt := oasDef.GetTykExtension()
		tykExt.Info.ID = "oas-api"
		tykExt.Info.Name = "OAS API"
		tykExt.Server.ListenPath.Value = "/oas-api/"
	})[0]
	loadedSpecs := ts.Gw.LoadAPI(classic, mcp, oasSpec)
	require.Len(t, loadedSpecs, 3)

	filterCases := []struct {
		name         string
		spec         *APISpec
		includeTypes string
		want         bool
	}{
		{name: "classic without include types", spec: loadedSpecs[0], want: true},
		{name: "mcp without include types", spec: loadedSpecs[1], want: false},
		{name: "mcp with explicit include type", spec: loadedSpecs[1], includeTypes: " json, mcp ", want: true},
	}
	for _, tc := range filterCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldIncludeAPI(tc.spec, tc.includeTypes))
		})
	}

	list, code := ts.Gw.handleGetAPIList(httptest.NewRequest(http.MethodGet, "/tyk/apis", nil))

	require.Equal(t, http.StatusOK, code)
	definitions := list.([]*apidef.APIDefinition)
	assert.ElementsMatch(t, []string{"classic-api", "oas-api"}, apiDefinitionIDs(definitions))

	list, code = ts.Gw.handleGetAPIList(httptest.NewRequest(http.MethodGet, "/tyk/apis?include_types=mcp", nil))

	require.Equal(t, http.StatusOK, code)
	definitions = list.([]*apidef.APIDefinition)
	assert.ElementsMatch(t, []string{"classic-api", "mcp-api", "oas-api"}, apiDefinitionIDs(definitions))

	oasList, code := ts.Gw.handleGetAPIListOAS(false)

	require.Equal(t, http.StatusOK, code)
	oasDefinitions := oasList.([]oas.OAS)
	require.Len(t, oasDefinitions, 1)
	assert.Equal(t, "oas-api", oasDefinitions[0].GetTykExtension().Info.ID)
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// STK-REQ-051:error_handling:negative
// STK-REQ-051:error_handling:nominal
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:negative
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:negative
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIInventoryGet(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	classic := BuildAPI(func(spec *APISpec) {
		spec.APIID = "classic-api"
		spec.Name = "Classic API"
	})[0]
	oasSpec := BuildOASAPI(func(oasDef *oas.OAS) {
		tykExt := oasDef.GetTykExtension()
		tykExt.Info.ID = "oas-api"
		tykExt.Info.Name = "OAS API"
		tykExt.Server.ListenPath.Value = "/oas-api/"
	})[0]
	loadedSpecs := ts.Gw.LoadAPI(classic, oasSpec)
	require.Len(t, loadedSpecs, 2)
	classic = loadedSpecs[0]

	got, code := ts.Gw.handleGetAPI(classic.APIID, false)

	require.Equal(t, http.StatusOK, code)
	classicDef := got.(*apidef.APIDefinition)
	assert.Equal(t, classic.APIID, classicDef.APIID)

	got, code = ts.Gw.handleGetAPI(classic.APIID, true)

	require.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, apiError(apidef.ErrOASGetForOldAPI.Error()), got)

	got, code = ts.Gw.handleGetAPI("missing-api", false)

	require.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, apiError(apidef.ErrAPINotFound.Error()), got)

	got, code = ts.Gw.handleGetAPIOAS("oas-api", true)

	require.Equal(t, http.StatusOK, code)
	publicOAS := got.(*oas.OAS)
	assert.Nil(t, publicOAS.GetTykExtension())

	got, code = ts.Gw.handleGetAPIOAS("oas-api", false)

	require.Equal(t, http.StatusOK, code)
	privateOAS := got.(*oas.OAS)
	require.NotNil(t, privateOAS.GetTykExtension())
	assert.Equal(t, "oas-api", privateOAS.GetTykExtension().Info.ID)
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// STK-REQ-051:error_handling:negative
// STK-REQ-051:error_handling:nominal
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:negative
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:negative
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIPersistenceWriteHelpers(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	appPath := "/apps"
	testFs := afero.NewMemMapFs()
	require.NoError(t, testFs.MkdirAll(appPath, 0755))

	conf := ts.Gw.GetConfig()
	conf.AppPath = appPath
	ts.Gw.SetConfig(conf, true)

	apiDef := apidef.DummyAPI()
	apiDef.APIID = "classic-api"

	err, code := ts.Gw.writeToFile(testFs, apiDef, apiDef.APIID)

	require.NoError(t, err)
	assert.Equal(t, 0, code)
	raw, err := afero.ReadFile(testFs, filepath.Join(appPath, "classic-api.json"))
	require.NoError(t, err)
	var writtenDef apidef.APIDefinition
	require.NoError(t, json.Unmarshal(raw, &writtenDef))
	assert.Equal(t, "classic-api", writtenDef.APIID)

	err, code = ts.Gw.writeToFile(testFs, apiDef, "../bad-api")

	require.EqualError(t, err, "invalid API ID")
	assert.Equal(t, http.StatusBadRequest, code)

	writeCases := []struct {
		name        string
		spec        *APISpec
		wantOASFile string
	}{
		{
			name: "oas writes native and oas documents",
			spec: BuildOASAPI(func(oasDef *oas.OAS) {
				tykExt := oasDef.GetTykExtension()
				tykExt.Info.ID = "oas-api"
				tykExt.Info.Name = "OAS API"
			})[0],
			wantOASFile: "oas-api-oas.json",
		},
		{
			name: "mcp writes native and mcp documents",
			spec: BuildOASAPI(func(oasDef *oas.OAS) {
				tykExt := oasDef.GetTykExtension()
				tykExt.Info.ID = "mcp-api"
				tykExt.Info.Name = "MCP API"
			})[0],
			wantOASFile: "mcp-api-mcp.json",
		},
	}
	writeCases[1].spec.MarkAsMCP()

	for _, tc := range writeCases {
		t.Run(tc.name, func(t *testing.T) {
			err, code := ts.Gw.writeOASAndAPIDefToFile(testFs, tc.spec.APIDefinition, &tc.spec.OAS)

			require.NoError(t, err)
			assert.Equal(t, 0, code)
			_, err = testFs.Stat(filepath.Join(appPath, tc.spec.APIID+".json"))
			require.NoError(t, err)
			_, err = testFs.Stat(filepath.Join(appPath, tc.wantOASFile))
			require.NoError(t, err)
		})
	}
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// STK-REQ-051:error_handling:negative
// STK-REQ-051:error_handling:nominal
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:negative
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:negative
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIAddUpdateDeleteHandlers(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	appPath := t.TempDir()
	testFs := afero.NewMemMapFs()
	require.NoError(t, testFs.MkdirAll(appPath, 0755))

	conf := ts.Gw.GetConfig()
	conf.AppPath = appPath
	ts.Gw.SetConfig(conf, true)

	newRequest := func(t *testing.T, method string, payload interface{}) *http.Request {
		t.Helper()
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		req, err := http.NewRequest(method, "http://gateway", bytes.NewBuffer(body))
		require.NoError(t, err)
		return req
	}

	t.Run("add classic api", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "added-api"

		response, code := ts.Gw.handleAddApi(newRequest(t, http.MethodPost, apiDef), testFs, false)

		require.Equal(t, http.StatusOK, code)
		success := response.(apiModifyKeySuccess)
		assert.Equal(t, "added-api", success.Key)
		assert.Equal(t, "added", success.Action)
		_, err := testFs.Stat(filepath.Join(appPath, "added-api.json"))
		require.NoError(t, err)
	})

	t.Run("add rejects malformed json", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "http://gateway", strings.NewReader("{"))
		require.NoError(t, err)

		response, code := ts.Gw.handleAddApi(req, testFs, false)

		require.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, apiError("Request malformed"), response)
	})

	existing := BuildAPI(func(spec *APISpec) {
		spec.APIID = "existing-api"
		spec.Name = "Existing API"
	})[0]
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = map[string]*APISpec{existing.APIID: existing}
	ts.Gw.apisMu.Unlock()

	t.Run("update classic api", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = existing.APIID

		response, code := ts.Gw.handleUpdateApi(existing.APIID, newRequest(t, http.MethodPut, apiDef), testFs, false)

		require.Equal(t, http.StatusOK, code)
		success := response.(apiModifyKeySuccess)
		assert.Equal(t, existing.APIID, success.Key)
		assert.Equal(t, "modified", success.Action)
	})

	t.Run("update rejects api id mismatch", func(t *testing.T) {
		apiDef := apidef.DummyAPI()
		apiDef.APIID = "different-api"

		response, code := ts.Gw.handleUpdateApi(existing.APIID, newRequest(t, http.MethodPut, apiDef), testFs, false)

		require.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, apiError("Request APIID does not match that in Definition! For Update operations these must match."), response)
	})

	t.Run("delete classic api", func(t *testing.T) {
		deleteSpec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "delete-api"
			spec.Name = "Delete API"
		})[0]
		ts.Gw.apisMu.Lock()
		ts.Gw.apisByID[deleteSpec.APIID] = deleteSpec
		ts.Gw.apisMu.Unlock()
		deletePath := filepath.Join(appPath, "delete-api.json")
		require.NoError(t, os.WriteFile(deletePath, []byte(`{"api_id":"delete-api"}`), 0644))

		response, code := ts.Gw.handleDeleteAPI(deleteSpec.APIID)

		require.Equal(t, http.StatusOK, code)
		success := response.(apiModifyKeySuccess)
		assert.Equal(t, "delete-api", success.Key)
		assert.Equal(t, "deleted", success.Action)
		_, err := os.Stat(deletePath)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("delete rejects missing api", func(t *testing.T) {
		response, code := ts.Gw.handleDeleteAPI("missing-api")

		require.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, apiError(apidef.ErrAPINotFound.Error()), response)
	})
}

// Verifies: STK-REQ-051, SYS-REQ-139, SW-REQ-126
// STK-REQ-051:STK-REQ-051-AC-01:acceptance
// STK-REQ-051:error_handling:negative
// STK-REQ-051:error_handling:nominal
// SYS-REQ-139:nominal:nominal
// SYS-REQ-139:boundary:nominal
// SYS-REQ-139:error_handling:negative
// SYS-REQ-139:error_handling:nominal
// SYS-REQ-139:determinism:nominal
// SW-REQ-126:nominal:nominal
// SW-REQ-126:boundary:nominal
// SW-REQ-126:error_handling:negative
// SW-REQ-126:error_handling:nominal
// SW-REQ-126:determinism:nominal
func TestGatewayControlAPIRouteHandlers(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	classic := BuildAPI(func(spec *APISpec) {
		spec.APIID = "route-classic"
		spec.Name = "Route Classic"
		spec.VersionDefinition.BaseID = "base-api"
	})[0]
	oasSpec := BuildOASAPI(func(oasDef *oas.OAS) {
		tykExt := oasDef.GetTykExtension()
		tykExt.Info.ID = "route-oas"
		tykExt.Info.Name = "Route OAS"
		tykExt.Server.ListenPath.Value = "/route-oas/"
	})[0]
	loadedSpecs := ts.Gw.LoadAPI(classic, oasSpec)
	require.Len(t, loadedSpecs, 2)
	loadedSpecs[0].VersionDefinition.BaseID = "base-api"

	t.Run("api handler gets a classic api and sets base header", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/tyk/apis/route-classic", nil), map[string]string{"apiID": "route-classic"})
		rec := httptest.NewRecorder()

		ts.Gw.apiHandler(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "base-api", rec.Header().Get(apidef.HeaderBaseAPIID))
		assert.Contains(t, rec.Body.String(), `"api_id":"route-classic"`)
	})

	t.Run("api handler rejects update without api id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/apis", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		ts.Gw.apiHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Must specify an apiID to update")
	})

	t.Run("oas get handler returns oas api", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/tyk/apis/oas/route-oas", nil), map[string]string{"apiID": "route-oas"})
		rec := httptest.NewRecorder()

		ts.Gw.apiOASGetHandler(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"x-tyk-api-gateway"`)
		assert.Contains(t, rec.Body.String(), `"id":"route-oas"`)
	})

	t.Run("oas post handler rejects malformed body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/tyk/apis/oas", strings.NewReader("{"))
		rec := httptest.NewRecorder()

		ts.Gw.apiOASPostHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Request malformed")
	})

	t.Run("oas put handler rejects update without api id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/apis/oas", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		ts.Gw.apiOASPutHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Must specify an apiID to update")
	})

	t.Run("oas patch handler rejects missing api id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/tyk/apis/oas", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		ts.Gw.apiOASPatchHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Must specify an apiID to patch")
	})

	t.Run("oas patch handler rejects classic api", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/tyk/apis/oas/route-classic", strings.NewReader(`{}`)), map[string]string{"apiID": "route-classic"})
		rec := httptest.NewRecorder()

		ts.Gw.apiOASPatchHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), apidef.ErrAPINotMigrated.Error())
	})
}

func apiDefinitionIDs(definitions []*apidef.APIDefinition) []string {
	ids := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		ids = append(ids, definition.APIID)
	}
	return ids
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:boundary:nominal
// SYS-REQ-140:error_handling:nominal
// SYS-REQ-140:determinism:nominal
// MCDC SYS-REQ-140: gateway_session_lifecycle_operation_terminal=T => TRUE
// SW-REQ-127:nominal:nominal
// SW-REQ-127:boundary:nominal
// SW-REQ-127:error_handling:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecycleTrialPeriod(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.KeyExpiresIn = 300
		p.PostExpiryAction = user.PostExpiryActionRetain
		p.PostExpiryGracePeriod = 45
	})

	existingSession := CreateStandardSession()
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession("existing-key", existingSession, 60, false))

	testCases := []struct {
		name        string
		keyName     string
		policyIDs   []string
		wantExpiry  bool
		wantPostExp bool
	}{
		{
			name:        "new key receives policy trial expiry and post expiry fields",
			keyName:     "new-key",
			policyIDs:   []string{policyID},
			wantExpiry:  true,
			wantPostExp: true,
		},
		{
			name:        "existing key keeps current expiry but receives post expiry fields",
			keyName:     "existing-key",
			policyIDs:   []string{policyID},
			wantPostExp: true,
		},
		{
			name:      "missing policy leaves session unchanged",
			keyName:   "missing-policy-key",
			policyIDs: []string{"missing-policy"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := CreateStandardSession()
			session.Expires = -1
			session.ApplyPolicies = tc.policyIDs

			before := time.Now().Unix()
			ts.Gw.checkAndApplyTrialPeriod(tc.keyName, session, false)

			if tc.wantExpiry {
				assert.GreaterOrEqual(t, session.Expires, before+300)
				assert.LessOrEqual(t, session.Expires, time.Now().Unix()+305)
			} else {
				assert.Equal(t, int64(-1), session.Expires)
			}

			if tc.wantPostExp {
				assert.Equal(t, user.PostExpiryActionRetain, session.PostExpiryAction)
				assert.Equal(t, int64(45), session.PostExpiryGracePeriod)
			} else {
				assert.Empty(t, session.PostExpiryAction)
				assert.Zero(t, session.PostExpiryGracePeriod)
			}
		})
	}
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:determinism:nominal
// SW-REQ-127:nominal:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecyclePolicySave(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "save-api"
		spec.OrgID = "default"
		spec.SessionLifetime = 120
	})

	session := CreateStandardSession()
	session.AccessRights = map[string]user.AccessDefinition{
		"save-api": {APIID: "save-api", Versions: []string{"Default"}},
	}

	require.NoError(t, ts.Gw.applyPoliciesAndSave("save-key", session, ts.Gw.getApiSpec("save-api"), false))

	stored, found := ts.Gw.GlobalSessionManager.SessionDetail("default", "save-key", false)
	require.True(t, found)
	assert.Equal(t, session.AccessRights, stored.AccessRights)
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// STK-REQ-052:error_handling:negative
// SYS-REQ-140:error_handling:negative
// SW-REQ-127:error_handling:negative
func TestGatewaySessionLifecyclePolicySaveRejectsPolicyErrors(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "error-api"
		spec.OrgID = "default"
	})

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.OrgID = "other-org"
		p.AccessRights = map[string]user.AccessDefinition{
			"error-api": {APIID: "error-api", Versions: []string{"Default"}},
		}
	})

	session := CreateStandardSession()
	session.ApplyPolicies = []string{policyID}
	session.AccessRights = map[string]user.AccessDefinition{
		"error-api": {APIID: "error-api", Versions: []string{"Default"}},
	}

	err := ts.Gw.applyPoliciesAndSave("policy-error-key", session, ts.Gw.getApiSpec("error-api"), false)

	require.Error(t, err)
	_, found := ts.Gw.GlobalSessionManager.SessionDetail("default", "policy-error-key", false)
	assert.False(t, found)
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:boundary:nominal
// SYS-REQ-140:determinism:nominal
// SW-REQ-127:nominal:nominal
// SW-REQ-127:boundary:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecycleAddOrUpdateStoresSessionMetadata(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "add-update-api"
		spec.OrgID = "default"
	})

	session := CreateStandardSession()
	session.QuotaRenewalRate = 300
	session.AccessRights = map[string]user.AccessDefinition{
		"add-update-api": {APIID: "add-update-api", Versions: []string{"Default"}},
	}

	before := time.Now().Unix()
	keyName := ts.Gw.generateToken(session.OrgID, "add-update-key")

	require.NoError(t, ts.Gw.doAddOrUpdate(keyName, session, false, false))

	stored, found := ts.Gw.GlobalSessionManager.SessionDetail("default", keyName, false)
	require.True(t, found)
	require.NotEmpty(t, stored.LastUpdated)
	lastUpdated, err := strconv.ParseInt(stored.LastUpdated, 10, 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, lastUpdated, before)
	assert.GreaterOrEqual(t, stored.QuotaRenews, before+session.QuotaRenewalRate)
	assert.Contains(t, stored.AccessRights, "add-update-api")
}

// Verifies: STK-REQ-052, SYS-REQ-140, SW-REQ-127
// STK-REQ-052:STK-REQ-052-AC-01:acceptance
// SYS-REQ-140:nominal:nominal
// SYS-REQ-140:boundary:nominal
// SYS-REQ-140:determinism:nominal
// SW-REQ-127:nominal:nominal
// SW-REQ-127:boundary:nominal
// SW-REQ-127:determinism:nominal
func TestGatewaySessionLifecycleAccessRightsAndLimits(t *testing.T) {
	specs := BuildAPI(
		func(spec *APISpec) {
			spec.APIID = "api-a"
		},
		func(spec *APISpec) {
			spec.APIID = "api-b"
		},
	)
	gw := &Gateway{
		apisByID: map[string]*APISpec{
			"api-a": specs[0],
			"api-b": specs[1],
		},
	}

	session := &user.SessionState{
		AccessRights: map[string]user.AccessDefinition{
			"api-a":       {APIID: "api-a"},
			"missing-api": {APIID: "missing-api"},
			"api-b":       {APIID: "api-b"},
		},
	}

	gotSpecs := gw.GetApiSpecsFromAccessRights(session)
	gotIDs := make([]string, 0, len(gotSpecs))
	for _, spec := range gotSpecs {
		gotIDs = append(gotIDs, spec.APIID)
	}
	assert.ElementsMatch(t, []string{"api-a", "api-b"}, gotIDs)
	assert.Empty(t, gw.GetApiSpecsFromAccessRights(nil))

	accessRights := map[string]user.AccessDefinition{
		"zero-limit": {APIID: "zero-limit", Limit: user.APILimit{}},
		"rate-limit": {
			APIID: "rate-limit",
			Limit: user.APILimit{RateLimit: user.RateLimit{Rate: 10, Per: 1}},
		},
	}
	resetAPILimits(accessRights)

	assert.Equal(t, user.APILimit{}, accessRights["zero-limit"].Limit)
	assert.Equal(t, user.APILimit{RateLimit: user.RateLimit{Rate: 10, Per: 1}}, accessRights["rate-limit"].Limit)
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:determinism:nominal
// MCDC SYS-REQ-141: gateway_key_management_operation_terminal=T => TRUE
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementBasicAuthHashing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testCases := []struct {
		name       string
		configured string
		wantHash   user.HashType
	}{
		{name: "default empty falls back to bcrypt", configured: "", wantHash: user.HashBCrypt},
		{name: "invalid falls back to bcrypt", configured: "invalid", wantHash: user.HashBCrypt},
		{name: "sha256 is preserved", configured: string(user.HashSha256), wantHash: user.HashSha256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := ts.Gw.GetConfig()
			conf.BasicAuthHashKeyFunction = tc.configured
			ts.Gw.SetConfig(conf)

			assert.Equal(t, string(tc.wantHash), ts.Gw.basicAuthHashAlgo())

			session := CreateStandardSession()
			session.BasicAuthData.Password = "password"
			ts.Gw.setBasicAuthSessionPassword(session)

			assert.Equal(t, tc.wantHash, session.BasicAuthData.Hash)
			assert.NotEqual(t, "password", session.BasicAuthData.Password)
			assert.NotEmpty(t, session.BasicAuthData.Password)
		})
	}
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// STK-REQ-053:error_handling:negative
// SYS-REQ-141:error_handling:negative
// SYS-REQ-141:encoding_safety:nominal
// SW-REQ-128:error_handling:negative
// SW-REQ-128:encoding_safety:nominal
func TestGatewayKeyManagementAddOrUpdateErrors(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("malformed request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/tyk/keys/bad", bytes.NewBufferString("{"))

		got, code := ts.Gw.handleAddOrUpdate("bad", req, false)

		require.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, apiError("Request malformed"), got)
	})

	t.Run("missing key update", func(t *testing.T) {
		session := CreateStandardSession()
		payload, err := json.Marshal(session)
		require.NoError(t, err)
		body := bytes.NewReader(payload)
		req := httptest.NewRequest(http.MethodPut, "/tyk/keys/missing-key", body)

		got, code := ts.Gw.handleAddOrUpdate("missing-key", req, false)

		require.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, apiError("Key is not found"), got)
	})
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementGetDetail(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.APIID = "detail-api"
		spec.OrgID = "default"
	})

	keyName := ts.Gw.generateToken("default", "detail-key")
	session := CreateStandardSession()
	session.QuotaMax = 10
	session.AccessRights = map[string]user.AccessDefinition{
		"detail-api": {
			APIID:          "detail-api",
			AllowanceScope: "detail-api",
			Limit: user.APILimit{
				QuotaMax: 5,
			},
		},
	}

	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(keyName, session, 0, false))
	globalQuotaKey := QuotaKeyPrefix + storage.HashKey(keyName, false)
	scopedQuotaKey := QuotaKeyPrefix + "detail-api-" + storage.HashKey(keyName, false)
	require.NoError(t, ts.Gw.GlobalSessionManager.Store().SetRawKey(globalQuotaKey, "3", 0))
	require.NoError(t, ts.Gw.GlobalSessionManager.Store().SetRawKey(scopedQuotaKey, "2", 0))

	got, code := ts.Gw.handleGetDetail(keyName, "detail-api", "default", false)

	require.Equal(t, http.StatusOK, code)
	detail, ok := got.(user.SessionState)
	require.True(t, ok)
	assert.Equal(t, int64(7), detail.QuotaRemaining)
	assert.Equal(t, int64(3), detail.AccessRights["detail-api"].Limit.QuotaRemaining)
	assert.Equal(t, keyName, detail.KeyID)

	basicAuthKey := ts.Gw.generateToken("default", "detail-basic-auth-key")
	basicAuthSession := CreateStandardSession()
	basicAuthSession.BasicAuthData.Password = "stored-password"
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(basicAuthKey, basicAuthSession, 0, false))

	got, code = ts.Gw.handleGetDetail(basicAuthKey, "detail-api", "default", false)

	require.Equal(t, http.StatusOK, code)
	detail, ok = got.(user.SessionState)
	require.True(t, ok)
	assert.Empty(t, detail.BasicAuthData.Password)
	assert.Equal(t, basicAuthKey, detail.KeyID)
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// STK-REQ-053:error_handling:negative
// STK-REQ-053:error_handling:nominal
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:error_handling:negative
// SYS-REQ-141:error_handling:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:error_handling:negative
// SW-REQ-128:error_handling:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementListKeys(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, keyA := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			"api-a": {APIID: "api-a", Versions: []string{"Default"}},
		}
	})
	_, keyB := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			"api-b": {APIID: "api-b", Versions: []string{"Default"}},
		}
	})

	all, code := ts.Gw.handleGetAllKeys(context.Background(), "default", "", false)
	require.Equal(t, http.StatusOK, code)
	allKeys := all.(apiAllKeys).APIKeys
	assert.Contains(t, allKeys, keyA)
	assert.Contains(t, allKeys, keyB)

	filtered, code := ts.Gw.handleGetAllKeys(context.Background(), "default", "api-a", false)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{keyA}, filtered.(apiAllKeys).APIKeys)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	timeout, code := ts.Gw.handleGetAllKeys(ctx, "default", "api-a", false)
	require.Equal(t, http.StatusGatewayTimeout, code)
	assert.Equal(t, apiError("Request timeout while processing keys"), timeout)
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// STK-REQ-053:error_handling:negative
// STK-REQ-053:error_handling:nominal
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:error_handling:negative
// SYS-REQ-141:error_handling:nominal
// SYS-REQ-141:encoding_safety:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:error_handling:negative
// SW-REQ-128:error_handling:nominal
// SW-REQ-128:encoding_safety:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementAddKeyStorageUpdate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	keyName := ts.Gw.generateToken("default", "add-key")
	session := CreateStandardSession()
	payload, err := json.Marshal(session)
	require.NoError(t, err)

	ts.Gw.handleAddKey(keyName, string(payload), "default")

	stored, found := ts.Gw.GlobalSessionManager.SessionDetail("default", keyName, ts.Gw.GetConfig().HashKeys)
	require.True(t, found)
	assert.Equal(t, "default", stored.OrgID)
	assert.NotEmpty(t, stored.LastUpdated)

	ts.Gw.handleAddKey("malformed-key", "{", "default")

	_, found = ts.Gw.GlobalSessionManager.SessionDetail("default", "malformed-key", ts.Gw.GetConfig().HashKeys)
	assert.False(t, found)

	orgMismatch := CreateStandardSession()
	orgMismatch.OrgID = "other"
	payload, err = json.Marshal(orgMismatch)
	require.NoError(t, err)

	ts.Gw.handleAddKey("org-mismatch-key", string(payload), "default")

	_, found = ts.Gw.GlobalSessionManager.SessionDetail("default", "org-mismatch-key", ts.Gw.GetConfig().HashKeys)
	assert.False(t, found)
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// STK-REQ-053:error_handling:negative
// STK-REQ-053:error_handling:nominal
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:error_handling:negative
// SYS-REQ-141:error_handling:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:error_handling:negative
// SW-REQ-128:error_handling:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementDeleteKeys(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	missing, code := ts.Gw.handleDeleteKey("missing-key", "default", "detail-api", false)
	require.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, apiError("There is no such key found"), missing)

	keyName := ts.Gw.generateToken("default", "delete-key")
	session := CreateStandardSession()
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(keyName, session, 0, false))

	deleted, code := ts.Gw.handleDeleteKey(keyName, "default", "detail-api", false)

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, apiModifyKeySuccess{Key: keyName, Status: "ok", Action: "deleted"}, deleted)
	_, found := ts.Gw.GlobalSessionManager.SessionDetail("default", keyName, false)
	assert.False(t, found)

	hashedKey := storage.HashKey(ts.Gw.generateToken("default", "hashed-delete-key"), true)
	hashedSession := CreateStandardSession()
	require.NoError(t, ts.Gw.GlobalSessionManager.UpdateSession(hashedKey, hashedSession, 0, true))

	deleted, code = ts.Gw.handleDeleteHashedKeyWithLogs(hashedKey, "default", "detail-api", false)

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, apiModifyKeySuccess{Key: hashedKey, Status: "ok", Action: "deleted"}, deleted)
	_, found = ts.Gw.GlobalSessionManager.SessionDetail("default", hashedKey, true)
	assert.False(t, found)

	missing, code = ts.Gw.handleDeleteHashedKeyWithLogs("missing-hashed-key", "default", "detail-api", false)
	require.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, apiError("There is no such key found"), missing)
}

// Verifies: STK-REQ-053, SYS-REQ-141, SW-REQ-128
// STK-REQ-053:STK-REQ-053-AC-01:acceptance
// STK-REQ-053:error_handling:nominal
// SYS-REQ-141:nominal:nominal
// SYS-REQ-141:boundary:nominal
// SYS-REQ-141:error_handling:nominal
// SYS-REQ-141:determinism:nominal
// SW-REQ-128:nominal:nominal
// SW-REQ-128:boundary:nominal
// SW-REQ-128:error_handling:nominal
// SW-REQ-128:determinism:nominal
func TestGatewayKeyManagementSortedSetForwarding(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	setKey := "reqproof-sorted-set-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ts.Gw.handleGlobalAddToSortedSet(setKey, "first", 1)
	ts.Gw.handleGlobalAddToSortedSet(setKey, "second", 2)

	values, scores, err := ts.Gw.handleGetSortedSetRange(setKey, "-inf", "+inf")

	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second"}, values)
	assert.Equal(t, []float64{1, 2}, scores)

	require.NoError(t, ts.Gw.handleRemoveSortedSetRange(setKey, "-inf", "+inf"))

	values, scores, err = ts.Gw.handleGetSortedSetRange(setKey, "-inf", "+inf")

	require.NoError(t, err)
	assert.Empty(t, values)
	assert.Empty(t, scores)
}

// Verifies: STK-REQ-054, SYS-REQ-142, SW-REQ-129
// STK-REQ-054:STK-REQ-054-AC-01:acceptance
// SYS-REQ-142:nominal:nominal
// SYS-REQ-142:boundary:nominal
// SYS-REQ-142:determinism:nominal
// MCDC SYS-REQ-142: gateway_policy_management_operation_terminal=T => TRUE
// SW-REQ-129:nominal:nominal
// SW-REQ-129:boundary:nominal
// SW-REQ-129:determinism:nominal
func TestGatewayPolicyManagementLookupAndList(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	missing, code := ts.Gw.handleGetPolicy("missing-policy")
	require.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, apiError("Policy not found"), missing)

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "policy-management-lookup"
	})

	got, code := ts.Gw.handleGetPolicy(policyID)

	require.Equal(t, http.StatusOK, code)
	policy, ok := got.(user.Policy)
	require.True(t, ok)
	assert.Equal(t, policyID, policy.ID)

	list, code := ts.Gw.handleGetPolicyList()

	require.Equal(t, http.StatusOK, code)
	assert.NotEmpty(t, list)

	conf := ts.Gw.GetConfig()
	conf.Policies.PolicyPath = ""
	ts.Gw.SetConfig(conf)

	root, err := ts.Gw.newPolicyPathRoot()

	require.NoError(t, err)
	assert.NotNil(t, root)
}

// Verifies: STK-REQ-054, SYS-REQ-142, SW-REQ-129
// STK-REQ-054:STK-REQ-054-AC-01:acceptance
// STK-REQ-054:error_handling:negative
// STK-REQ-054:error_handling:nominal
// SYS-REQ-142:nominal:nominal
// SYS-REQ-142:boundary:nominal
// SYS-REQ-142:error_handling:negative
// SYS-REQ-142:error_handling:nominal
// SYS-REQ-142:encoding_safety:nominal
// SYS-REQ-142:determinism:nominal
// SW-REQ-129:nominal:nominal
// SW-REQ-129:boundary:nominal
// SW-REQ-129:error_handling:negative
// SW-REQ-129:error_handling:nominal
// SW-REQ-129:encoding_safety:nominal
// SW-REQ-129:determinism:nominal
func TestGatewayPolicyManagementAddOrUpdate(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policyDir := t.TempDir()
	conf := ts.Gw.GetConfig()
	conf.Policies.PolicyPath = policyDir
	conf.Policies.PolicySource = "file"
	conf.AllowUnsafePolicyIds = false
	ts.Gw.SetConfig(conf)

	policy := user.Policy{
		ID:           "policy-management",
		Rate:         100,
		Per:          1,
		OrgID:        "default",
		AccessRights: map[string]user.AccessDefinition{},
	}
	payload, err := json.Marshal(policy)
	require.NoError(t, err)

	created, code := ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(payload)))

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, apiModifyKeySuccess{Key: policy.ID, Status: "ok", Action: "added"}, created)
	assert.FileExists(t, policyDir+"/"+policy.ID+".json")

	updated, code := ts.Gw.handleAddOrUpdatePolicy(policy.ID, httptest.NewRequest(http.MethodPut, "/tyk/policies/"+policy.ID, bytes.NewReader(payload)))

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, apiModifyKeySuccess{Key: policy.ID, Status: "ok", Action: "modified"}, updated)

	malformed, code := ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", strings.NewReader("{")))
	require.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, apiError("Request malformed"), malformed)

	missingID, err := json.Marshal(user.Policy{})
	require.NoError(t, err)
	rejected, code := ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(missingID)))
	require.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, apiError("Unable to create policy without id."), rejected)

	invalidID := policy
	invalidID.ID = "invalid/id"
	invalidPayload, err := json.Marshal(invalidID)
	require.NoError(t, err)
	rejected, code = ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(invalidPayload)))
	require.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, apiError(identifier.ErrInvalidCustomPolicyId.Error()), rejected)

	mismatch := policy
	mismatch.ID = "body-id"
	mismatchPayload, err := json.Marshal(mismatch)
	require.NoError(t, err)
	rejected, code = ts.Gw.handleAddOrUpdatePolicy("path-id", httptest.NewRequest(http.MethodPut, "/tyk/policies/path-id", bytes.NewReader(mismatchPayload)))
	require.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, apiError("Request ID does not match that in policy! For Update operations these must match."), rejected)

	conf = ts.Gw.GetConfig()
	conf.Policies.PolicySource = "service"
	ts.Gw.SetConfig(conf)
	rejected, code = ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(payload)))
	require.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, apiError("Due to enabled service policy source, please use the Dashboard API"), rejected)

	conf.Policies.PolicySource = "file"
	conf.Policies.PolicyPath = "api.go"
	ts.Gw.SetConfig(conf)
	rejected, code = ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(payload)))
	require.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, apiError("Unable to access policy storage."), rejected)
}

// Verifies: STK-REQ-054, SYS-REQ-142, SW-REQ-129
// STK-REQ-054:STK-REQ-054-AC-01:acceptance
// STK-REQ-054:error_handling:negative
// STK-REQ-054:error_handling:nominal
// SYS-REQ-142:nominal:nominal
// SYS-REQ-142:boundary:nominal
// SYS-REQ-142:error_handling:negative
// SYS-REQ-142:error_handling:nominal
// SYS-REQ-142:determinism:nominal
// SW-REQ-129:nominal:nominal
// SW-REQ-129:boundary:nominal
// SW-REQ-129:error_handling:negative
// SW-REQ-129:error_handling:nominal
// SW-REQ-129:determinism:nominal
func TestGatewayPolicyManagementDeletePolicy(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policyDir := t.TempDir()
	conf := ts.Gw.GetConfig()
	conf.Policies.PolicyPath = policyDir
	conf.Policies.PolicySource = "file"
	ts.Gw.SetConfig(conf)

	policy := user.Policy{
		ID:           "delete-policy",
		Rate:         100,
		Per:          1,
		OrgID:        "default",
		AccessRights: map[string]user.AccessDefinition{},
	}
	payload, err := json.Marshal(policy)
	require.NoError(t, err)
	_, code := ts.Gw.handleAddOrUpdatePolicy("", httptest.NewRequest(http.MethodPost, "/tyk/policies", bytes.NewReader(payload)))
	require.Equal(t, http.StatusOK, code)

	deleted, code := ts.Gw.handleDeletePolicy(policy.ID)

	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, apiModifyKeySuccess{Key: policy.ID, Status: "ok", Action: "deleted"}, deleted)
	assert.NoFileExists(t, policyDir+"/"+policy.ID+".json")

	missing, code := ts.Gw.handleDeletePolicy("missing-policy")
	require.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, apiError("Delete failed"), missing)

	conf = ts.Gw.GetConfig()
	conf.Policies.PolicyPath = "api.go"
	ts.Gw.SetConfig(conf)
	failed, code := ts.Gw.handleDeletePolicy(policy.ID)
	require.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, apiError("Delete failed"), failed)
}

// Verifies: STK-REQ-054, SYS-REQ-142, SW-REQ-129
// STK-REQ-054:STK-REQ-054-AC-01:acceptance
// STK-REQ-054:error_handling:negative
// STK-REQ-054:error_handling:nominal
// SYS-REQ-142:nominal:nominal
// SYS-REQ-142:boundary:nominal
// SYS-REQ-142:error_handling:negative
// SYS-REQ-142:error_handling:nominal
// SYS-REQ-142:determinism:nominal
// SW-REQ-129:nominal:nominal
// SW-REQ-129:boundary:nominal
// SW-REQ-129:error_handling:negative
// SW-REQ-129:error_handling:nominal
// SW-REQ-129:determinism:nominal
func TestGatewayPolicyManagementRouteHandler(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	policyID := ts.CreatePolicy(func(p *user.Policy) {
		p.ID = "policy-route"
	})

	t.Run("get dispatches to policy lookup", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/tyk/policies/policy-route", nil), map[string]string{"polID": policyID})
		rec := httptest.NewRecorder()

		ts.Gw.polHandler(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"id":"policy-route"`)
	})

	t.Run("put without policy id is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/tyk/policies", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		ts.Gw.polHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Must specify an apiID to update")
	})

	t.Run("delete without policy id is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/tyk/policies", nil)
		rec := httptest.NewRecorder()

		ts.Gw.polHandler(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "Must specify an apiID to delete")
	})
}
