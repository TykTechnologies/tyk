package gateway

import (
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

func (a *APISpec) GetMiddlewareMetadata(r *http.Request, mode apidef.URLStatus) (interface{}, bool) {
	vInfo, _ := a.Version(r)
	versionPaths := a.RxPaths[vInfo.Name]
	found, meta := a.CheckSpecMatchesStatus(r, versionPaths, mode)

	log.Debug("Checking spec matches status")
	log.Debugf("Request URL: %s", r.URL.String())
	log.Debugf("Request method: %s", r.Method)
	log.Debugf("URL status mode: %v", mode)
	log.Debugf("Number of RxPaths: %d", len(versionPaths))
	log.Debugf("Found: %v, Meta: %+v", found, meta)

	return meta, found
}

// CheckSpecMatchesStatus checks if a URL spec has a specific status.
// Deprecated: The function doesn't follow go return conventions (T, ok); use FindSpecMatchesStatus;
func (a *APISpec) CheckSpecMatchesStatus(r *http.Request, rxPaths []URLSpec, mode URLStatus) (bool, interface{}) {
	matchPath, method := a.getMatchPathAndMethod(r, mode)

	log.Debugf("Match path: %s", matchPath)
	log.Debugf("Match method: %s", method)

	for i := range rxPaths {
		if rxPaths[i].Status != mode {
			log.Debugf("Skipping path: status mismatch. Expected: %v, Got: %v", mode, rxPaths[i].Status)
			continue
		}
		log.Debugf("Checking method match for path: %s", rxPaths[i].spec)
		if !rxPaths[i].matchesMethod(method) {
			log.Debugf("Skipping path: method mismatch. Expected: %s", method)
			continue
		}

		log.Debugf("Checking path match for: %s", matchPath)
		if !rxPaths[i].matchesPath(matchPath, a) {
			log.Debugf("Skipping path: path mismatch")
			continue
		}

		log.Debug("Checking for mode specific spec")
		if spec, ok := rxPaths[i].modeSpecificSpec(mode); ok {
			log.Debugf("Found matching spec for mode: %v", mode)
			return true, spec
		}
		log.Debug("No mode specific spec found")
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
