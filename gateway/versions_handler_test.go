package gateway_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/test"
)

func TestHandleListAPIVersions(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("native definition", func(t *testing.T) {
		const (
			baseVersionName = "base-version-name"
			v1APIID         = "v1-api-id"
			v1VersionName   = "v1-version-name"
			v2APIID         = "v2-api-id"
			v2VersionName   = "v2-version-name"
		)
		baseAPIFunc := func(baseVersion string) func(a *APISpec) {
			return func(a *APISpec) {
				a.APIID = "base"
				a.Proxy.ListenPath = "/default"
				a.UseKeylessAccess = true
				a.VersionDefinition.Enabled = true
				a.VersionDefinition.Name = baseVersionName
				a.VersionDefinition.Default = v2VersionName
				a.VersionDefinition.Location = apidef.URLParamLocation
				a.VersionDefinition.Key = "version"
				a.VersionDefinition.Versions = map[string]string{
					v1VersionName: v1APIID,
					v2VersionName: v2APIID,
				}
			}
		}

		baseAPI := BuildAPI(baseAPIFunc(baseVersionName))[0]

		v1 := BuildAPI(func(a *APISpec) {
			a.APIID = v1APIID
			a.Name = "v1-api-name"
			a.Proxy.ListenPath = "/v1-listen-path"
			a.UseKeylessAccess = false
			a.Internal = true
		})[0]

		v2 := BuildAPI(func(a *APISpec) {
			a.APIID = v2APIID
			a.Name = "v2-api-name"
			a.Proxy.ListenPath = "/v2-listen-path"
			a.UseKeylessAccess = false
			a.Internal = false
		})[0]

		ts.Gw.LoadAPI(baseAPI, v1, v2)

		path := fmt.Sprintf("/tyk/apis/%s/versions", baseAPI.APIID)

		t.Run("default", func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 3)
					assert.True(t, metas.Metas[1].Internal)
					assert.False(t, metas.Metas[1].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[1].VersionName)
					return true
				}})
		})

		t.Run("filter by searchText", func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				QueryParams: map[string]string{"searchText": "V1"},
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 1)
					assert.True(t, metas.Metas[0].Internal)
					assert.False(t, metas.Metas[0].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[0].VersionName)

					return true
				}})
		})

		t.Run("filter by accessType", func(t *testing.T) {
			t.Run("internal", func(t *testing.T) {
				_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
					QueryParams: map[string]string{"accessType": "internal"},
					BodyMatchFunc: func(resp []byte) bool {
						var metas VersionMetas
						err := json.Unmarshal(resp, &metas)
						assert.NoError(t, err)

						assert.Len(t, metas.Metas, 1)
						assert.True(t, metas.Metas[0].Internal)
						assert.False(t, metas.Metas[0].IsDefaultVersion)
						assert.Equal(t, v1VersionName, metas.Metas[0].VersionName)

						return true
					}})
			})

			t.Run("external", func(t *testing.T) {
				_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
					QueryParams: map[string]string{"accessType": "external"},
					BodyMatchFunc: func(resp []byte) bool {
						var metas VersionMetas
						err := json.Unmarshal(resp, &metas)
						assert.NoError(t, err)

						assert.Len(t, metas.Metas, 2)
						assert.False(t, metas.Metas[1].Internal)
						assert.True(t, metas.Metas[1].IsDefaultVersion)
						assert.Equal(t, v2VersionName, metas.Metas[1].VersionName)

						return true
					}})
			})
		})

		t.Run("always keep base API as the first element regardless of version name sort in default list", func(t *testing.T) {
			// start base version with x to verify sort isn't changing position of base API in versions list
			newBaseAPI := BuildAPI(baseAPIFunc("x-base-api-version"))[0]
			ts.Gw.LoadAPI(newBaseAPI, v1, v2)
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 3)
					assert.True(t, metas.Metas[1].Internal)
					assert.False(t, metas.Metas[1].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[1].VersionName)
					return true
				}})
		})
	})

	t.Run("oas definition", func(t *testing.T) {
		const (
			baseVersionName = "base-version-name"
			v1APIID         = "v1-api-id"
			v1VersionName   = "v1-version-name"
			v2APIID         = "v2-api-id"
			v2VersionName   = "v2-version-name"
		)

		baseAPIFunc := func(baseVersion string) func(oasDef *oas.OAS) {
			return func(oasDef *oas.OAS) {
				tykExt := oasDef.GetTykExtension()
				tykExt.Info.ID = "base"
				tykExt.Info.Name = "base-api"
				tykExt.Server.ListenPath.Value = "/default"
				tykExt.Info.Versioning = &oas.Versioning{
					Enabled:  true,
					Name:     baseVersion,
					Default:  v2VersionName,
					Location: apidef.URLParamLocation,
					Key:      "version",
					Versions: []oas.VersionToID{
						{
							Name: v1VersionName,
							ID:   v1APIID,
						},
						{
							Name: v2VersionName,
							ID:   v2APIID,
						},
					},
				}
			}
		}

		baseAPI := BuildOASAPI(baseAPIFunc(baseVersionName))[0]

		v1 := BuildOASAPI(func(oasDef *oas.OAS) {
			tykExt := oasDef.GetTykExtension()
			tykExt.Info.ID = v1APIID
			tykExt.Info.Name = "v1-api-name"
			tykExt.Server.ListenPath.Value = "/v1-listen-path"
			tykExt.Info.State.Internal = true
		})[0]

		v2 := BuildOASAPI(func(oasDef *oas.OAS) {
			tykExt := oasDef.GetTykExtension()
			tykExt.Info.ID = v2APIID
			tykExt.Info.Name = "v2-api-name"
			tykExt.Server.ListenPath.Value = "/v2-listen-path"
			tykExt.Info.State.Internal = false
		})[0]

		ts.Gw.LoadAPI(baseAPI, v1, v2)

		path := fmt.Sprintf("/tyk/apis/oas/%s/versions", baseAPI.APIID)

		t.Run("default", func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 3)
					assert.True(t, metas.Metas[1].Internal)
					assert.False(t, metas.Metas[1].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[1].VersionName)
					return true
				}})
		})

		t.Run("filter by searchText", func(t *testing.T) {
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				QueryParams: map[string]string{"searchText": "V1"},
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 1)
					assert.True(t, metas.Metas[0].Internal)
					assert.False(t, metas.Metas[0].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[0].VersionName)

					return true
				}})
		})

		t.Run("filter by accessType", func(t *testing.T) {
			t.Run("internal", func(t *testing.T) {
				_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
					QueryParams: map[string]string{"accessType": "internal"},
					BodyMatchFunc: func(resp []byte) bool {
						var metas VersionMetas
						err := json.Unmarshal(resp, &metas)
						assert.NoError(t, err)

						assert.Len(t, metas.Metas, 1)
						assert.True(t, metas.Metas[0].Internal)
						assert.False(t, metas.Metas[0].IsDefaultVersion)
						assert.Equal(t, v1VersionName, metas.Metas[0].VersionName)

						return true
					}})
			})

			t.Run("external", func(t *testing.T) {
				_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
					QueryParams: map[string]string{"accessType": "external"},
					BodyMatchFunc: func(resp []byte) bool {
						var metas VersionMetas
						err := json.Unmarshal(resp, &metas)
						assert.NoError(t, err)

						assert.Len(t, metas.Metas, 2)
						assert.False(t, metas.Metas[1].Internal)
						assert.True(t, metas.Metas[1].IsDefaultVersion)
						assert.Equal(t, v2VersionName, metas.Metas[1].VersionName)

						return true
					}})
			})
		})

		t.Run("always keep base API as the first element regardless of version name sort in default list", func(t *testing.T) {
			// start base version with x to verify sort isn't changing position of base API in versions list
			newBaseAPI := BuildOASAPI(baseAPIFunc("x-base-api-version"))[0]
			ts.Gw.LoadAPI(newBaseAPI, v1, v2)
			_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: path,
				BodyMatchFunc: func(resp []byte) bool {
					var metas VersionMetas
					err := json.Unmarshal(resp, &metas)
					assert.NoError(t, err)

					assert.Len(t, metas.Metas, 3)
					assert.True(t, metas.Metas[1].Internal)
					assert.False(t, metas.Metas[1].IsDefaultVersion)
					assert.Equal(t, v1VersionName, metas.Metas[1].VersionName)
					return true
				}})
		})
	})

}
