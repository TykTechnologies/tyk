package gateway

import (
	"bytes"
	"errors"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"net/http"
	"text/template"
)

type ErrorOverrideMiddleware struct {
	*BaseMiddleware
}

func (e *ErrorOverrideMiddleware) Name() string {
	return "ErrorOverrideMiddleware"
}

func (e *ErrorOverrideMiddleware) EnabledForSpec() bool {
	return true // Always enabled
}

func (e *ErrorOverrideMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	errorInfo := ctx.GetErrorInfo(r)
	if errorInfo == nil {
		return nil, http.StatusOK
	}

	newMsg, newCode := e.ApplyErrorOverride(r, errorInfo.Message, errorInfo.Code)
	if newMsg != errorInfo.Message || newCode != errorInfo.Code {
		ctx.SetErrorInfo(r, errorInfo.ErrorID, errorInfo.OriginalErr, nil)
	}

	return errors.New(newMsg), newCode
}

func (e *ErrorOverrideMiddleware) ApplyErrorOverride(r *http.Request, errMsg string, errCode int) (string, int) {
	// Get error ID from context or determine it
	errorInfo := ctx.GetErrorInfo(r)

	errorID := e.extractErrorID(errorInfo, errMsg, errCode)
	if errorID == "" {
		return errMsg, errCode
	}

	details := map[string]interface{}{}
	if errorInfo != nil {
		details = errorInfo.Details
	}

	// Endpoint-level override
	if vInfo, _ := e.Spec.Version(r); vInfo != nil {
		if override, found := e.findEndpointErrorOverride(r, vInfo.Name, errorID); found {
			return e.applyOverride(override, errMsg, errCode, details)
		}
	}

	// API-level override
	if override, found := e.Spec.CustomErrorResponses[errorID]; found {
		return e.applyOverride(override, errMsg, errCode, details)
	}

	// here we might set the gw level errors¿

	return errMsg, errCode
}

func (e *ErrorOverrideMiddleware) extractErrorID(info *ctx.ErrorContext, fallbackMsg string, fallbackCode int) string {
	if info != nil && info.ErrorID != "" {
		return info.ErrorID
	}
	return e.determineErrorID(fallbackMsg, fallbackCode)
}

func (e *ErrorOverrideMiddleware) applyOverride(override apidef.TykError, defaultMsg string, defaultCode int, details map[string]interface{}) (string, int) {
	msg := defaultMsg
	code := defaultCode

	if override.Message != "" {
		rendered, err := renderMessage(override.Message, details)
		if err == nil {
			msg = rendered
		}
		// If render fails, fall back to default message
	}
	if override.Code != 0 {
		code = override.Code
	}

	return msg, code
}

func renderMessage(tmplStr string, data any) (string, error) {
	tmpl, err := template.New("msg").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// determineErrorID attempts to identify the error type based on message and code
func (e *ErrorOverrideMiddleware) determineErrorID(errMsg string, errCode int) string {
	// Try exact match first
	for id, err := range TykErrors {
		if err.Message == errMsg && err.Code == errCode {
			return id
		}
	}

	// Try message-only match
	for id, err := range TykErrors {
		if err.Message == errMsg {
			return id
		}
	}

	// Try code-only match
	for id, err := range TykErrors {
		if err.Code == errCode && errCode != 0 {
			return id
		}
	}

	return ""
}

func (e *ErrorOverrideMiddleware) findEndpointErrorOverride(r *http.Request, versionName, errorID string) (apidef.TykError, bool) {
	if versionInfo, ok := e.Spec.VersionData.Versions[versionName]; ok {
		path := r.URL.Path
		path = e.Spec.StripListenPath(path)

		for _, override := range versionInfo.ExtendedPaths.ErrorOverrides {
			if override.Path == path && (override.Method == r.Method || override.Method == "") {
				if errorOverride, exists := override.Errors[errorID]; exists {
					return errorOverride, true
				}
			}
		}
	}

	return apidef.TykError{}, false
}
