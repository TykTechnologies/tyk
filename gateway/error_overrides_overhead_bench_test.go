package gateway

import (
	htmltemplate "html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

func benchApplyOrFallback(handler *ErrorHandler, gw *Gateway, w http.ResponseWriter, req *http.Request) {
	if gw.GetCompiledErrorOverrides() == nil {
		handler.writeTemplateErrorResponse(w, req, benchInternalServerError, 500)
		return
	}
	eo := NewErrorOverrides(handler.Spec, handler.Gw)
	if result := eo.ApplyOverride(req, 500, []byte("error")); result != nil {
		handler.writeOverrideResponse(w, req, result, "error")
		return
	}
	handler.writeTemplateErrorResponse(w, req, benchInternalServerError, 500)
}

func BenchmarkErrorHandlerOverhead(b *testing.B) {
	jsonTemplate := htmltemplate.Must(htmltemplate.New("error.json").Parse(`{"error": "{{.Message}}"}`))

	cases := []struct {
		name      string
		overrides apidef.ErrorOverridesMap
		baseline  bool
	}{
		{
			name:     "baseline - no override infrastructure",
			baseline: true,
		},
		{
			name: "with override check - none configured",
		},
		{
			name: "with override check - overrides configured but not matching",
			overrides: apidef.ErrorOverridesMap{
				"404": []apidef.ErrorOverride{{
					Response: apidef.ErrorResponse{Message: "Not found"},
				}},
			},
		},
		{
			name: "with override check - overrides matching",
			overrides: apidef.ErrorOverridesMap{
				"500": []apidef.ErrorOverride{{
					Response: apidef.ErrorResponse{StatusCode: 503, Message: `{"error": "Service unavailable"}`},
				}},
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			gw := &Gateway{}
			gw.templates = jsonTemplate
			if tc.overrides != nil {
				gw.SetCompiledErrorOverrides(CompileErrorOverrides(tc.overrides))
			}
			handler := &ErrorHandler{
				BaseMiddleware: &BaseMiddleware{
					Spec: &APISpec{GlobalConfig: config.Config{}},
					Gw:   gw,
				},
			}
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(header.ContentType, header.ApplicationJSON)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				if tc.baseline {
					handler.writeTemplateErrorResponse(w, req, benchInternalServerError, 500)
				} else {
					benchApplyOrFallback(handler, gw, w, req)
				}
			}
		})
	}
}
