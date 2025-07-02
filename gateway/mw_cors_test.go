package gateway

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware_ProcessRequest_PreflightRequest(t *testing.T) {
	corsConf := createCORSConfig()
	m := createCORSMiddleware(corsConf)
	m.Init()

	origin := "http://example.com"
	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")

	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, req, nil)
	assert.Nil(t, err)
	assert.Equal(t, middleware.StatusRespond, code, "Should respond immediately for preflight requests")

	resp := w.Result()
	assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), http.MethodPost)
}

func TestCORSMiddleware_ProcessRequest_RegularRequest(t *testing.T) {
	corsConf := createCORSConfig()
	m := createCORSMiddleware(corsConf)
	m.Init()

	origin := "http://example.com"
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	err, code := m.ProcessRequest(w, req, nil)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, code, "Should continue middleware chain for regular requests")

	resp := w.Result()
	assert.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, resp.Header.Get("Access-Control-Expose-Headers"), "X-Rate-Limit")
}

func TestCORSMiddleware_testApi(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	api1ID := uuid.New()
	api2ID := uuid.New()

	apis := g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "CORS test API"
		spec.APIID = api1ID
		spec.Proxy.ListenPath = "/cors-api/"
		spec.CORS.Enable = false
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	}, func(spec *APISpec) {
		spec.Name = "Another API"
		spec.APIID = api2ID
		spec.Proxy.ListenPath = "/another-api/"
		spec.CORS.ExposedHeaders = []string{"Custom-Header"}
		spec.CORS.AllowedOrigins = []string{"*"}
	})

	headers := map[string]string{
		"Origin": "my-custom-origin",
	}

	headersMatch := map[string]string{
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Expose-Headers": "Custom-Header",
	}

	t.Run("CORS disabled", func(t *testing.T) {
		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("CORS enabled", func(t *testing.T) {
		apis[0].CORS.Enable = true
		g.Gw.LoadAPI(apis...)

		_, _ = g.Run(t, []test.TestCase{
			{Path: "/cors-api/", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusOK},
			{Path: "/another-api/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
			{Path: "/" + api1ID + "/", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusOK},
			{Path: "/" + api2ID + "/", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusOK},
		}...)
	})

	t.Run("oauth endpoints", func(t *testing.T) {
		apis[0].UseOauth2 = true
		apis[0].CORS.Enable = false

		g.Gw.LoadAPI(apis...)

		t.Run("CORS disabled", func(t *testing.T) {
			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersNotMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})

		t.Run("CORS enabled", func(t *testing.T) {
			apis[0].CORS.Enable = true
			g.Gw.LoadAPI(apis...)

			_, _ = g.Run(t, []test.TestCase{
				{Path: "/cors-api/oauth/token", Headers: headers, HeadersMatch: headersMatch, Code: http.StatusForbidden},
			}...)
		})
	})
}

func createCORSConfig() apidef.CORSConfig {
	return apidef.CORSConfig{
		Enable:             true,
		AllowedOrigins:     []string{"http://example.com"},
		AllowedMethods:     []string{"GET", "POST"},
		AllowedHeaders:     []string{"Content-Type", "Authorization"},
		ExposedHeaders:     []string{"X-Rate-Limit"},
		AllowCredentials:   true,
		MaxAge:             86400,
		OptionsPassthrough: false,
		Debug:              false,
	}
}

func createCORSMiddleware(corsConf apidef.CORSConfig) *CORSMiddleware {
	return &CORSMiddleware{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					CORS: corsConf,
				},
			},
		},
	}
}
