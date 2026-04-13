package gateway

import (
	"bytes"
	"html"
	htmltemplate "html/template"
	"io"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/header"
)

// ErrorResponseContext holds content-type detection results for error responses.
// Used to determine template extension and template engine selection.
type ErrorResponseContext struct {
	// ContentType is the Content-Type header value to use in the response.
	ContentType string

	// TemplateExtension is the file extension for template lookup ("json" or "xml").
	TemplateExtension string

	// IsXML indicates whether XML content type was detected.
	// When true, text/template is used; otherwise html/template is used.
	IsXML bool
}

// DetectErrorResponseContext extracts content type info from the request.
// Follows the same pattern as writeTemplateErrorResponse for consistency.
func DetectErrorResponseContext(r *http.Request) *ErrorResponseContext {
	contentType := r.Header.Get(header.ContentType)
	contentType = strings.Split(contentType, ";")[0]

	switch contentType {
	case header.ApplicationXML:
		return &ErrorResponseContext{
			ContentType:       header.ApplicationXML,
			TemplateExtension: "xml",
			IsXML:             true,
		}
	case header.TextXML:
		return &ErrorResponseContext{
			ContentType:       header.TextXML,
			TemplateExtension: "xml",
			IsXML:             true,
		}
	default:
		return &ErrorResponseContext{
			ContentType:       header.ApplicationJSON,
			TemplateExtension: "json",
			IsXML:             false,
		}
	}
}

// SetErrorResponseHeaders sets common error response headers on both the
// ResponseWriter and returns a copy for analytics recording.
func (e *ErrorHandler) SetErrorResponseHeaders(w http.ResponseWriter, contentType string) http.Header {
	respHeader := http.Header{}

	w.Header().Set(header.ContentType, contentType)
	respHeader.Set(header.ContentType, contentType)

	if !e.Spec.GlobalConfig.HideGeneratorHeader {
		w.Header().Add(header.XGenerator, "tyk.io")
		respHeader.Add(header.XGenerator, "tyk.io")
	}

	if e.Spec.GlobalConfig.CloseConnections {
		w.Header().Add(header.Connection, "close")
		respHeader.Add(header.Connection, "close")
	}

	return respHeader
}

// escapeTemplateString prepares s for safe rendering by the appropriate template engine.
// For JSON (html/template): JS-escapes and marks safe to prevent HTML entity encoding.
// For XML (text/template): HTML-escapes explicitly since text/template does not auto-escape.
func escapeTemplateString(s string, isXML bool) htmltemplate.HTML {
	if isXML {
		return htmltemplate.HTML(html.EscapeString(s))
	}
	return htmltemplate.HTML(htmltemplate.JSEscapeString(s))
}

// ExecuteErrorTemplate executes a template and captures output for analytics.
// Uses io.MultiWriter to write to both the response and a buffer for recording.
func (e *ErrorHandler) ExecuteErrorTemplate(w http.ResponseWriter, tmpl TemplateExecutor, data any, errCode int) *http.Response {
	w.WriteHeader(errCode)

	var log bytes.Buffer
	rsp := io.MultiWriter(w, &log)
	//nolint:errcheck // Consistent with writeTemplateErrorResponse - error can't be handled after headers written
	tmpl.Execute(rsp, data)

	return &http.Response{
		StatusCode: errCode,
		Body:       io.NopCloser(&log),
	}
}
