package ctx

import (
	"context"
	"github.com/TykTechnologies/tyk/internal/service/core"
	"net/http"
)

type ErrorContext struct {
	ErrorID     string
	Message     string
	Code        int
	OriginalErr error
	Details     ErrorContextData
}

func GetErrorInfo(r *http.Request) *ErrorContext {
	if v := r.Context().Value(ErrorInfo); v != nil {
		if val, ok := v.(*ErrorContext); ok {
			return val
		}
	}
	return nil
}

func SetErrorInfo(r *http.Request, errorID string, originalErr error, data ErrorContextData) {
	ctx := r.Context()
	ctx = context.WithValue(ctx, ErrorInfo, &ErrorContext{
		ErrorID:     errorID,
		OriginalErr: originalErr,
		Details:     data,
	})
	core.SetContext(r, ctx)
}

type ErrorContextData map[string]interface{}

// BuildTemplateContext sets a contract on which fields are exposed via template
func BuildTemplateContext(details map[string]interface{}, errorID string, originalErr error) ErrorContextData {
	res := map[string]interface{}{
		"error_id": errorID,
		"details":  details,
	}

	if originalErr != nil {
		res["original_error"] = originalErr.Error()
	}

	return ErrorContextData(res)
}
