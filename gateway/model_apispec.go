package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/routers"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/agentprotocol"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/graphengine"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/user"

	_ "github.com/TykTechnologies/tyk/internal/mcp" // registers MCP VEM prefixes
)

// APISpec represents a path specification for an API, to avoid enumerating multiple nested lists, a single
// flattened URL list is checked for matching paths and then it's status evaluated if found.
type APISpec struct {
	*apidef.APIDefinition
	OAS oas.OAS

	sync.RWMutex

	Checksum         string
	RxPaths          map[string][]URLSpec
	WhiteListEnabled map[string]bool
	target           *url.URL
	AuthManager      SessionHandler
	OAuthManager     OAuthManagerInterface

	OrgSessionManager        SessionHandler
	EventPaths               map[apidef.TykEvent][]config.TykEventHandler
	Health                   HealthChecker
	JSVM                     JSVM
	ResponseChain            []TykResponseHandler
	RoundRobin               RoundRobin
	URLRewriteEnabled        bool
	CircuitBreakerEnabled    bool
	EnforcedTimeoutEnabled   bool
	LastGoodHostList         *apidef.HostList
	HasRun                   bool
	ServiceRefreshInProgress bool
	HTTPTransport            *TykRoundTripper
	HTTPTransportCreated     time.Time
	WSTransport              http.RoundTripper
	WSTransportCreated       time.Time
	GlobalConfig             config.Config
	OrgHasNoSession          bool
	AnalyticsPluginConfig    *GoAnalyticsPlugin

	unloadHooks []func()

	network analytics.NetworkStats

	GraphEngine graphengine.Engine

	oasRouter routers.Router

	// UpstreamCertExpiryBatcher handles upstream certificate expiry checking
	UpstreamCertExpiryBatcher      certcheck.BackgroundBatcher
	upstreamCertExpiryCheckContext context.Context
	upstreamCertExpiryCancelFunc   context.CancelFunc
	upstreamCertExpiryInitOnce     sync.Once

	// MCPPrimitives maps primitive identifiers to their VEM paths for JSON-RPC routing.
	// Key format: "tool:{name}", "resource:{pattern}", "prompt:{name}"
	// Value: VEM path (e.g., "/mcp-tool:get-weather")
	MCPPrimitives map[string]string

	// MCPAllowListEnabled is true if any MCP primitive (tool, resource, prompt) has an
	// allow rule enabled. Pre-calculated during API loading to avoid iterating through
	// all primitives on every JSON-RPC request that doesn't match a VEM.
	MCPAllowListEnabled bool
}

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

func (a *APISpec) GetTykExtension() *oas.XTykAPIGateway {
	if !a.IsOAS {
		return nil
	}
	res := a.OAS.GetTykExtension()
	if res == nil {
		log.Warn("APISpec is an invalid OAS API")
	}
	return res
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

// FindAllVEMChainSpecs returns all URLSpecs matching the given status from the VEM chain.
// For MCP APIs with JSON-RPC routing, this returns specs from all VEMs in the chain
// (operation VEM + tool VEM), allowing middleware to be applied at each stage.
// For non-MCP APIs, it returns only the spec matching the current path.
func (a *APISpec) FindAllVEMChainSpecs(r *http.Request, rxPaths []URLSpec, mode URLStatus) []*URLSpec {
	// Check if this is a JSON-RPC routed request with a VEM chain
	rpcData := httpctx.GetJSONRPCRequest(r)

	log.Infof("[DEBUG] FindAllVEMChainSpecs: mode=%v, path=%s, hasRPCData=%v", mode, r.URL.Path, rpcData != nil)
	if rpcData != nil {
		log.Infof("[DEBUG] FindAllVEMChainSpecs: VEMChain=%v, VEMPath=%s", rpcData.VEMChain, rpcData.VEMPath)
	}

	if rpcData == nil || len(rpcData.VEMChain) == 0 {
		// Not a JSON-RPC request, use normal logic
		log.Infof("[DEBUG] FindAllVEMChainSpecs: No VEM chain, using normal logic")
		if spec, ok := a.FindSpecMatchesStatus(r, rxPaths, mode); ok {
			return []*URLSpec{spec}
		}
		return nil
	}

	// For JSON-RPC requests, find all specs matching VEMs in the chain
	method := http.MethodPost // JSON-RPC always uses POST
	var specs []*URLSpec

	log.Infof("[DEBUG] FindAllVEMChainSpecs: Checking %d VEMs in chain", len(rpcData.VEMChain))
	for _, vemPath := range rpcData.VEMChain {
		log.Infof("[DEBUG] FindAllVEMChainSpecs: Looking for specs matching VEM: %s", vemPath)
		for i := range rxPaths {
			if rxPaths[i].Status != mode {
				continue
			}
			if !rxPaths[i].matchesMethod(method) {
				continue
			}

			// Check if this spec matches the VEM path
			// We need to get the path from the spec based on the mode
			specPath, specMethod := a.getSpecPathAndMethod(&rxPaths[i], mode)
			if specPath == vemPath && specMethod == method {
				log.Infof("[DEBUG] FindAllVEMChainSpecs: Found matching spec at path=%s", specPath)
				specs = append(specs, &rxPaths[i])
				break // Found spec for this VEM, move to next
			}
		}
	}

	log.Infof("[DEBUG] FindAllVEMChainSpecs: Returning %d specs", len(specs))
	return specs
}

// getSpecPathAndMethod extracts the path and method from a URLSpec based on the mode.
func (a *APISpec) getSpecPathAndMethod(spec *URLSpec, mode URLStatus) (string, string) {
	switch mode {
	case RateLimit:
		return spec.RateLimit.Path, spec.RateLimit.Method
	case HeaderInjected:
		return spec.InjectHeaders.Path, spec.InjectHeaders.Method
	case HeaderInjectedResponse:
		return spec.InjectHeadersResponse.Path, spec.InjectHeadersResponse.Method
	case Transformed:
		return spec.TransformAction.Path, spec.TransformAction.Method
	case TransformedResponse:
		return spec.TransformResponseAction.Path, spec.TransformResponseAction.Method
	case Cached:
		if meta := spec.CacheConfig.CacheOnlyResponseCodes; len(meta) > 0 {
			// CacheConfig doesn't have Path/Method, use the URLSpec's regex matcher instead
			// This is a limitation - we can't directly get path from cache config
			// For now, skip caching in VEM chain - it can be added later if needed
		}
		return "", ""
	case CircuitBreaker:
		return spec.CircuitBreaker.Path, spec.CircuitBreaker.Method
	case URLRewrite:
		if spec.URLRewrite != nil {
			return spec.URLRewrite.Path, spec.URLRewrite.Method
		}
	case HardTimeout:
		return spec.HardTimeout.Path, spec.HardTimeout.Method
	case RequestSizeLimit:
		return spec.RequestSize.Path, spec.RequestSize.Method
	case VirtualPath:
		return spec.VirtualPathSpec.Path, spec.VirtualPathSpec.Method
	}
	return "", ""
}

// isJSONRPCVEMPath returns true if the request is a JSON-RPC routed request
// targeting a protocol VEM path. In this case, the listen path should not be
// stripped as the VEM path is already in its final form.
func isJSONRPCVEMPath(r *http.Request, path string) bool {
	return httpctx.IsJsonRPCRouting(r) && agentprotocol.IsProtocolVEMPath(path)
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

	if a.Proxy.ListenPath != "/" && !isJSONRPCVEMPath(r, matchPath) {
		matchPath = a.StripListenPath(matchPath)
	}

	if !strings.HasPrefix(matchPath, "/") {
		matchPath = "/" + matchPath
	}

	return matchPath, method
}

func (a *APISpec) injectIntoReqContext(req *http.Request) {
	if a.IsOAS {
		ctx.SetOASDefinition(req, &a.OAS)
	} else {
		ctx.SetDefinition(req, a.APIDefinition)
	}
}

func (a *APISpec) findOperation(r *http.Request) *Operation {
	middleware := a.OAS.GetTykMiddleware()
	if middleware == nil {
		return nil
	}

	if a.oasRouter == nil {
		log.Warningf("OAS router not initialized properly. Unable to find route for %s %v", r.Method, r.URL)
		return nil
	}

	rClone := *r
	rClone.URL = ctxGetInternalRedirectTarget(r)

	route, pathParams, err := a.oasRouter.FindRoute(&rClone)

	if errors.Is(err, routers.ErrPathNotFound) {
		log.Tracef("Unable to find route for %s %v at spec %v", r.Method, r.URL, a.Id)
		return nil
	}

	if err != nil {
		log.Errorf("Error finding route: %v", err)
		return nil
	}

	operation, ok := middleware.Operations[route.Operation.OperationID]
	if !ok {
		log.Warningf("No operation found for ID: %s", route.Operation.OperationID)
		return nil
	}

	return &Operation{
		Operation:  operation,
		route:      route,
		pathParams: pathParams,
	}
}

// findRouteForOASPath finds the OAS route using the OAS path pattern (e.g., "/users/{id}")
// and method, rather than the actual request path. This is used when gateway path matching
// (prefix/suffix) matches a broader pattern than the exact OAS path.
// The actualPath parameter is the request path stripped of the listen path.
// The fullRequestPath is the original request path (used for regexp listen paths).
func (a *APISpec) findRouteForOASPath(oasPath, method, actualPath, fullRequestPath string) (*routers.Route, map[string]string, error) {
	if a.oasRouter == nil {
		return nil, nil, errors.New("OAS router not initialized")
	}

	// For listen paths with mux-style variables (regexp), we need to use the actual
	// request path because the OAS router's server URL contains the variable pattern.
	// For regular listen paths, we build a synthetic path.
	var routePath string
	if httputil.IsMuxTemplate(a.Proxy.ListenPath) {
		// For regexp listen paths like /product-regexp1/{name:.*}
		// Use the full request path as the OAS router expects actual values
		routePath = fullRequestPath
	} else {
		// For regular listen paths, combine listen path + OAS path
		routePath = strings.TrimSuffix(a.Proxy.ListenPath, "/") + oasPath
	}

	syntheticURL, err := url.Parse(routePath)
	if err != nil {
		return nil, nil, err
	}

	syntheticReq := &http.Request{
		Method: method,
		URL:    syntheticURL,
	}

	route, _, err := a.oasRouter.FindRoute(syntheticReq)
	if err != nil {
		return nil, nil, err
	}

	// Extract path parameters from the actual request path by matching against
	// the OAS path pattern. This handles cases where the OAS path has parameters
	// like /users/{id} and we need to extract the actual id value from the request.
	pathParams := extractPathParams(oasPath, actualPath)

	return route, pathParams, nil
}

// extractPathParams extracts path parameter values from actualPath based on the
// OAS path pattern. For example, if oasPath is "/users/{id}" and actualPath is
// "/users/123", it returns map[string]string{"id": "123"}.
func extractPathParams(oasPath, actualPath string) map[string]string {
	params := make(map[string]string)

	oasParts := strings.Split(strings.Trim(oasPath, "/"), "/")
	actualParts := strings.Split(strings.Trim(actualPath, "/"), "/")

	for i, oasPart := range oasParts {
		if i >= len(actualParts) {
			break
		}
		// Check if this is a path parameter (wrapped in {})
		if strings.HasPrefix(oasPart, "{") && strings.HasSuffix(oasPart, "}") {
			paramName := oasPart[1 : len(oasPart)-1]
			params[paramName] = actualParts[i]
		}
	}

	return params
}

func (a *APISpec) sendRateLimitHeaders(session *user.SessionState, dest *http.Response) {
	quotaMax, quotaRemaining, quotaRenews := int64(0), int64(0), int64(0)

	if session != nil {
		quotaMax, quotaRemaining, _, quotaRenews = session.GetQuotaLimitByAPIID(a.APIID)
	}

	if dest.Header == nil {
		dest.Header = http.Header{}
	}

	dest.Header.Set(header.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
	dest.Header.Set(header.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
	dest.Header.Set(header.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
}
