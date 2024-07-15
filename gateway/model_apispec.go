package gateway

import (
	"net/http"
	"strings"
)

// CheckSpecMatchesStatus checks if a URL spec has a specific status.
// Deprecated: The function doesn't follow go return conventions (T, ok); use FindSpecMatchesStatus;
func (a *APISpec) CheckSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	matchPath, method := a.getMatchPathAndMethod(r, mode)

	for i := range rxPaths {
		if rxPaths[i].Status != mode {
			continue
		}
		if !rxPaths[i].Spec.MatchString(matchPath) {
			continue
		}

		if rxPaths[i].matchesMethod(method) {
			if spec, ok := rxPaths[i].modeSpecificSpec(mode); ok {
				return true, spec
			}
		}
	}
	return false, nil
}

// FindSpecMatchesStatus checks if a URL spec has a specific status and returns the URLSpec for it.
func (a *APISpec) FindSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (*URLSpec, bool) {
	matchPath, method := a.getMatchPathAndMethod(r, mode)

	for i := range rxPaths {
		if rxPaths[i].Status != mode {
			continue
		}
		if !rxPaths[i].Spec.MatchString(matchPath) {
			continue
		}

		if rxPaths[i].matchesMethod(method) {
			if _, ok := rxPaths[i].modeSpecificSpec(mode); ok {
				return &rxPaths[i], ok
			}
		}
	}
	return nil, false
}

// getMatchPathAndMethod retrieves the match path and method from the request based on the mode.
func (a *APISpec) getMatchPathAndMethod(r *http.Request, mode URLStatus) (string, string) {
	var matchPath, method string

	if mode == TransformedJQResponse || mode == HeaderInjectedResponse || mode == TransformedResponse {
		matchPath = ctxGetUrlRewritePath(r)
		method = ctxGetRequestMethod(r)
		if matchPath == "" {
			matchPath = r.URL.Path
		}
	} else {
		matchPath = r.URL.Path
		method = r.Method
	}

	if a.Proxy.ListenPath != "/" {
		matchPath = strings.TrimPrefix(matchPath, a.Proxy.ListenPath)
	}

	if !strings.HasPrefix(matchPath, "/") {
		matchPath = "/" + matchPath
	}

	return matchPath, method
}
