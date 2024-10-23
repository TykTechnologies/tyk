package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

type MultiAuthMiddleware struct {
    *BaseMiddleware
    handlers []AuthenticationHandler
}

type AuthenticationHandler interface {
    ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int)
    Name() string
}

func (m *MultiAuthMiddleware) Name() string {
    return "MultiAuthMiddleware"
}

func (m *MultiAuthMiddleware) EnabledForSpec() bool {
    return m.Spec.IsOAS && // Use IsOAS flag from APISpec
           m.Spec.OAS.GetTykExtension() != nil &&
           m.Spec.OAS.GetTykExtension().Server.Authentication != nil &&
           m.Spec.OAS.GetTykExtension().Server.Authentication.MultiSchemeEnabled
}

func (m *MultiAuthMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
    auth := m.Spec.OAS.GetTykExtension().Server.Authentication
    
    if auth.Strategy == oas.AuthStrategyAny { // Reference constant from oas package
        return m.processAny(w, r)
    }
    
    return m.processAll(w, r)
}

// processAny implements OR logic - succeeds if any auth method succeeds
func (m *MultiAuthMiddleware) processAny(w http.ResponseWriter, r *http.Request) (error, int) {
	var lastErr error
	var lastCode int
	
	for _, handler := range m.handlers {
		if err, code := handler.ProcessRequest(w, r, nil); err == nil {
			return nil, http.StatusOK
		} else {
			lastErr = err
			lastCode = code
		}
	}
	
	// If we get here, all auth methods failed
	return lastErr, lastCode
}

// processAll implements AND logic - succeeds only if all auth methods succeed
func (m *MultiAuthMiddleware) processAll(w http.ResponseWriter, r *http.Request) (error, int) {
	for _, handler := range m.handlers {
		if err, code := handler.ProcessRequest(w, r, nil); err != nil {
			return err, code
		}
	}
	
	return nil, http.StatusOK
}
