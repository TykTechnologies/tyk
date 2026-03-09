package gateway

import (
	htmltemplate "html/template"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
)

func BenchmarkErrorHandlerOverhead(b *testing.B) {
	b.Run("baseline - no override infrastructure", func(b *testing.B) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
		}
	})

	b.Run("with override check - none configured", func(b *testing.B) {
		gw := &Gateway{}
		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			if gw.GetCompiledErrorOverrides() != nil {
				overrides := NewErrorOverrides(handler.Spec, handler.Gw)
				if result := overrides.ApplyOverride(req, 500, []byte("error")); result != nil {
					handler.writeOverrideResponse(w, req, result, "error")
				} else {
					handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
				}
			} else {
				handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
			}
		}
	})

	b.Run("with override check - overrides configured but not matching", func(b *testing.B) {
		overrides := config.ErrorOverridesMap{
			"404": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Message: "Not found",
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)

		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			if gw.GetCompiledErrorOverrides() != nil {
				overrides := NewErrorOverrides(handler.Spec, handler.Gw)
				if result := overrides.ApplyOverride(req, 500, []byte("error")); result != nil {
					handler.writeOverrideResponse(w, req, result, "error")
				} else {
					handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
				}
			} else {
				handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
			}
		}
	})

	b.Run("with override check - overrides matching", func(b *testing.B) {
		overrides := config.ErrorOverridesMap{
			"500": []config.ErrorOverride{
				{
					Response: config.ErrorResponse{
						Code:    503,
						Message: `{"error": "Service unavailable"}`,
					},
				},
			},
		}

		gw := &Gateway{}
		compiled := CompileErrorOverrides(overrides)
		gw.SetCompiledErrorOverrides(compiled)

		jsonTmpl := htmltemplate.Must(htmltemplate.New("error.json").Parse(
			`{"error": "{{.Message}}"}`,
		))
		gw.templates = jsonTmpl

		handler := &ErrorHandler{
			BaseMiddleware: &BaseMiddleware{
				Spec: &APISpec{
					GlobalConfig: config.Config{},
				},
				Gw: gw,
			},
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set(header.ContentType, header.ApplicationJSON)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			if gw.GetCompiledErrorOverrides() != nil {
				overrides := NewErrorOverrides(handler.Spec, handler.Gw)
				if result := overrides.ApplyOverride(req, 500, []byte("error")); result != nil {
					handler.writeOverrideResponse(w, req, result, "error")
				} else {
					handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
				}
			} else {
				handler.writeTemplateErrorResponse(w, req, "Internal server error", 500)
			}
		}
	})
}
