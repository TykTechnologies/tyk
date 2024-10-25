package gateway

import (
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/internal/model"
)

// CheckSpecMatchesStatus checks if a URL spec has a specific status.
// Deprecated: The function doesn't follow go return conventions (T, ok); use FindSpecMatchesStatus;
func (a *APISpec) CheckSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	matchPath, method := a.getMatchPathAndMethod(r, mode)

	for i := range rxPaths {
		if rxPaths[i].Status != mode {
			continue
		}
		if !rxPaths[i].matchesMethod(method) {
			continue
		}
		if !rxPaths[i].matchesPath(matchPath, a) {
			continue
		}

		if spec, ok := rxPaths[i].modeSpecificSpec(mode); ok {
			return true, spec
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
		if !rxPaths[i].matchesMethod(method) {
			continue
		}
		if !rxPaths[i].matchesPath(matchPath, a) {
			continue
		}

		return &rxPaths[i], true
	}
	return nil, false
}

// getMatchPathAndMethod retrieves the match path and method from the request based on the mode.
func (a *APISpec) getMatchPathAndMethod(r *http.Request, mode URLStatus) (string, string) {
	var (
		matchPath = r.URL.Path
		method    = r.Method
	)

	if mode == TransformedJQResponse || mode == HeaderInjectedResponse || mode == TransformedResponse {
		matchPath = ctxGetUrlRewritePath(r)
		method = ctxGetRequestMethod(r)
		if matchPath == "" {
			matchPath = r.URL.Path
		}
	}

	if a.Proxy.ListenPath != "/" {
		matchPath = a.StripListenPath(matchPath)
	}

	if !strings.HasPrefix(matchPath, "/") {
		matchPath = "/" + matchPath
	}

	return matchPath, method
}

// MergedAPI provides a model.MergedAPI from an APISpec.
func (a *APISpec) MergedAPI() model.MergedAPI {
	return model.NewMergedAPI(a.APIDefinition, &a.OAS)
}
