package gateway

import (
	"errors"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"net/http"
	"strings"
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
		ctx.SetErrorInfo(r, errorInfo.ErrorID, errorInfo.OriginalErr)
	}

	return errors.New(newMsg), newCode
}

func (e *ErrorOverrideMiddleware) ApplyErrorOverride(r *http.Request, errMsg string, errCode int) (string, int) {
	// Get error ID from context or determine it
	errorInfo := ctx.GetErrorInfo(r)
	errorID := ""

	//ToDo this error must be injected in context from other middlewares
	errorID = ErrAuthKeyNotFound
	//ToDo: test with request validation
	// ToDo: add headers

	if errorInfo != nil && errorInfo.ErrorID != "" {
		errorID = errorInfo.ErrorID
	} else {
		errorID = e.determineErrorID(errMsg, errCode)
	}
	errorID = ErrAuthKeyNotFound
	if errorID == "" {
		return errMsg, errCode
	}

	// Check endpoint-level overrides first
	vInfo, _ := e.Spec.Version(r)
	if override, found := e.findEndpointErrorOverride(r, vInfo.Name, errorID); found {
		if override.Message != "" {
			errMsg = override.Message
		}
		if override.Code != 0 {
			errCode = override.Code
		}
		return errMsg, errCode
	}

	// Fall back to API-level overrides
	if override, exists := e.Spec.ErrorMessages[errorID]; exists {
		if override.Message != "" {
			errMsg = override.Message
		}
		if override.Code != 0 {
			errCode = override.Code
		}
	}

	return errMsg, errCode
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
		path = strings.TrimPrefix(path, "/")

		// Try exact path and method match
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
