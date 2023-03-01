package gateway

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/trace"
)

const (
	rateLimitEndpoint = "/tyk/rate-limits/"
)

type ChainObject struct {
	ThisHandler    http.Handler
	RateLimitChain http.Handler
	Open           bool
	Skip           bool
}

func (gw *Gateway) prepareStorage() generalStores {
	var gs generalStores
	gs.redisStore = &storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: gw.GetConfig().HashKeys, RedisController: gw.RedisController}
	gs.redisOrgStore = &storage.RedisCluster{KeyPrefix: "orgkey.", RedisController: gw.RedisController}
	gs.healthStore = &storage.RedisCluster{KeyPrefix: "apihealth.", RedisController: gw.RedisController}
	gs.rpcAuthStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: gw.GetConfig().HashKeys, Gw: gw}
	gs.rpcOrgStore = &RPCStorageHandler{KeyPrefix: "orgkey.", Gw: gw}
	gw.GlobalSessionManager.Init(gs.redisStore)
	return gs
}

func (gw *Gateway) skipSpecBecauseInvalid(spec *APISpec, logger *logrus.Entry) bool {

	switch spec.Protocol {
	case "", "http", "https":
		if spec.Proxy.ListenPath == "" {
			logger.Error("Listen path is empty")
			return true
		}
		if strings.Contains(spec.Proxy.ListenPath, " ") {
			logger.Error("Listen path contains spaces, is invalid")
			return true
		}
	}
	if val, err := gw.kvStore(spec.Proxy.TargetURL); err == nil {
		spec.Proxy.TargetURL = val
	}

	_, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		logger.Error("couldn't parse target URL: ", err)
		return true
	}

	return false
}

func generateDomainPath(hostname, listenPath string) string {
	return hostname + listenPath
}

func countApisByListenHash(specs []*APISpec) map[string]int {
	count := make(map[string]int, len(specs))
	// We must track the hostname no matter what
	for _, spec := range specs {
		domain := spec.GetAPIDomain()
		domainHash := generateDomainPath(domain, spec.Proxy.ListenPath)
		if count[domainHash] == 0 {
			dN := domain
			if dN == "" {
				dN = "(no host)"
			}
			mainLog.WithFields(logrus.Fields{
				"api_name": spec.Name,
				"domain":   dN,
			}).Info("Tracking hostname")
		}
		count[domainHash]++
	}
	return count
}

func fixFuncPath(pathPrefix string, funcs []apidef.MiddlewareDefinition) {
	for index := range funcs {
		funcs[index].Path = filepath.Join(pathPrefix, funcs[index].Path)
	}
}

func (gw *Gateway) generateSubRoutes(spec *APISpec, subRouter *mux.Router, logger *logrus.Entry) {
	if spec.GraphQL.GraphQLPlayground.Enabled {
		gw.loadGraphQLPlayground(spec, subRouter)
	}

	if spec.EnableBatchRequestSupport {
		gw.addBatchEndpoint(spec, subRouter)
	}

	if spec.UseOauth2 {
		logger.Debug("Loading OAuth Manager")
		oauthManager := gw.addOAuthHandlers(spec, subRouter)
		logger.Debug("-- Added OAuth Handlers")

		spec.OAuthManager = oauthManager
		logger.Debug("Done loading OAuth Manager")
	}
}

func (gw *Gateway) processSpec(spec *APISpec, apisByListen map[string]int,
	gs *generalStores, logger *logrus.Entry) *ChainObject {

	var chainDef ChainObject

	logger = logger.WithFields(logrus.Fields{
		"org_id":   spec.OrgID,
		"api_id":   spec.APIID,
		"api_name": spec.Name,
	})

	var coprocessLog = logger.WithFields(logrus.Fields{
		"prefix": "coprocess",
	})

	if spec.Proxy.Transport.SSLMaxVersion > 0 {
		spec.Proxy.Transport.SSLMaxVersion = tls.VersionTLS12
	}

	if spec.Proxy.Transport.SSLMinVersion > spec.Proxy.Transport.SSLMaxVersion {
		spec.Proxy.Transport.SSLMaxVersion = spec.Proxy.Transport.SSLMinVersion
	}

	if len(spec.TagHeaders) > 0 {
		// Ensure all headers marked for tagging are lowercase
		lowerCaseHeaders := make([]string, len(spec.TagHeaders))
		for i, k := range spec.TagHeaders {
			lowerCaseHeaders[i] = strings.ToLower(k)

		}
		spec.TagHeaders = lowerCaseHeaders
	}

	if gw.skipSpecBecauseInvalid(spec, logger) {
		logger.Warning("Spec not valid, skipped!")
		chainDef.Skip = true
		return &chainDef
	}

	// Expose API only to looping
	if spec.Internal {
		chainDef.Skip = true
	}

	pathModified := false
	for {
		domain := spec.GetAPIDomain()
		hash := generateDomainPath(domain, spec.Proxy.ListenPath)

		if apisByListen[hash] < 2 {
			// not a duplicate
			break
		}
		if !pathModified {
			prev := gw.getApiSpec(spec.APIID)
			if prev != nil && prev.Proxy.ListenPath == spec.Proxy.ListenPath {
				// if this APIID was already loaded and
				// had this listen path, let it keep it.
				break
			}
			spec.Proxy.ListenPath += "-" + spec.APIID
			pathModified = true
		} else {
			// keep adding '_' chars
			spec.Proxy.ListenPath += "_"
		}
	}
	if pathModified {
		logger.Error("Listen path collision, changed to ", spec.Proxy.ListenPath)
	}

	// Set up LB targets:
	if spec.Proxy.EnableLoadBalancing {
		sl := apidef.NewHostListFromList(spec.Proxy.Targets)
		spec.Proxy.StructuredTargetList = sl
	}

	// Initialise the auth and session managers (use Redis for now)
	authStore := gs.redisStore
	orgStore := gs.redisOrgStore
	switch spec.AuthProvider.StorageEngine {
	case LDAPStorageEngine:
		storageEngine := LDAPStorageHandler{}
		storageEngine.LoadConfFromMeta(spec.AuthProvider.Meta)
		authStore = &storageEngine
	case RPCStorageEngine:
		authStore = gs.rpcAuthStore
		orgStore = gs.rpcOrgStore
		spec.GlobalConfig.EnforceOrgDataAge = true
		globalConf := gw.GetConfig()
		globalConf.EnforceOrgDataAge = true
		gw.SetConfig(globalConf)
	}

	sessionStore := gs.redisStore
	switch spec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = gs.rpcAuthStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis storage pool
	spec.Init(authStore, sessionStore, gs.healthStore, orgStore)

	// Set up all the JSVM middleware
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostAuthCheckFuncs := []apidef.MiddlewareDefinition{}
	mwResponseFuncs := []apidef.MiddlewareDefinition{}

	var mwDriver apidef.MiddlewareDriver

	var prefix string
	if !spec.CustomMiddlewareBundleDisabled && spec.CustomMiddlewareBundle != "" {
		prefix = gw.getBundleDestPath(spec)
	}

	logger.Debug("Initializing API")
	var mwPaths []string

	mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwResponseFuncs, mwDriver = gw.loadCustomMiddleware(spec)
	if gw.GetConfig().EnableJSVM && (spec.hasVirtualEndpoint() || mwDriver == apidef.OttoDriver) {
		logger.Debug("Loading JS Paths")
		spec.JSVM.LoadJSPaths(mwPaths, prefix)
	}

	//  if bundle was used - fix paths for goplugin-type custom middle-wares
	if mwDriver == apidef.GoPluginDriver && prefix != "" {
		mwAuthCheckFunc.Path = filepath.Join(prefix, mwAuthCheckFunc.Path)
		fixFuncPath(prefix, mwPreFuncs)
		fixFuncPath(prefix, mwPostFuncs)
		fixFuncPath(prefix, mwPostAuthCheckFuncs)
		fixFuncPath(prefix, mwResponseFuncs)
	}

	enableVersionOverrides := false
	for _, versionData := range spec.VersionData.Versions {
		if versionData.OverrideTarget != "" && !spec.VersionData.NotVersioned {
			enableVersionOverrides = true
			break
		}
	}

	// Already vetted
	spec.target, _ = url.Parse(spec.Proxy.TargetURL)

	var proxy ReturningHttpHandler
	if enableVersionOverrides {
		logger.Info("Multi target enabled")
		proxy = gw.NewMultiTargetProxy(spec, logger)
	} else {
		proxy = gw.TykNewSingleHostReverseProxy(spec.target, spec, logger)
	}

	// Create the response processors, pass all the loaded custom middleware response functions:
	gw.createResponseMiddlewareChain(spec, mwResponseFuncs)

	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy, logger: logger, Gw: gw}

	for _, v := range baseMid.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			baseMid.Spec.CircuitBreakerEnabled = true
		}
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			baseMid.Spec.EnforcedTimeoutEnabled = true
		}
	}

	keyPrefix := "cache-" + spec.APIID
	cacheStore := storage.RedisCluster{KeyPrefix: keyPrefix, IsCache: true, RedisController: gw.RedisController}
	cacheStore.Connect()

	var chain http.Handler
	var chainArray []alice.Constructor
	var authArray []alice.Constructor

	if spec.UseKeylessAccess {
		chainDef.Open = true
		logger.Info("Checking security policy: Open")
	}

	gw.mwAppendEnabled(&chainArray, &VersionCheck{BaseMiddleware: baseMid})

	for _, obj := range mwPreFuncs {
		if mwDriver == apidef.GoPluginDriver {
			gw.mwAppendEnabled(
				&chainArray,
				&GoPluginMiddleware{
					BaseMiddleware: baseMid,
					Path:           obj.Path,
					SymbolName:     obj.Name,
					APILevel:       true,
				},
			)
		} else if mwDriver != apidef.OttoDriver {
			coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
			gw.mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver, obj.RawBodyOnly, nil})
		} else {
			chainArray = append(chainArray, gw.createDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
		}
	}

	gw.mwAppendEnabled(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &IPBlackListMiddleware{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &CertificateCheckMW{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid, mon: Monitor{Gw: gw}})
	gw.mwAppendEnabled(&chainArray, &RequestSizeLimitMiddleware{baseMid})
	gw.mwAppendEnabled(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &TrackEndpointMiddleware{baseMid})

	if !spec.UseKeylessAccess {
		// Select the keying method to use for setting session states
		if gw.mwAppendEnabled(&authArray, &Oauth2KeyExists{baseMid}) {
			logger.Info("Checking security policy: OAuth")
		}

		if gw.mwAppendEnabled(&authArray, &ExternalOAuthMiddleware{baseMid}) {
			logger.Info("Checking security policy: External OAuth")
		}

		if gw.mwAppendEnabled(&authArray, &BasicAuthKeyIsValid{baseMid, nil, nil}) {
			logger.Info("Checking security policy: Basic")
		}

		if gw.mwAppendEnabled(&authArray, &HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid}) {
			logger.Info("Checking security policy: HMAC")
		}

		if gw.mwAppendEnabled(&authArray, &JWTMiddleware{baseMid}) {
			logger.Info("Checking security policy: JWT")
		}

		if gw.mwAppendEnabled(&authArray, &OpenIDMW{BaseMiddleware: baseMid}) {
			logger.Info("Checking security policy: OpenID")
		}

		customPluginAuthEnabled := spec.CustomPluginAuthEnabled || spec.UseGoPluginAuth || spec.EnableCoProcessAuth

		if customPluginAuthEnabled && !mwAuthCheckFunc.Disabled {
			switch spec.CustomMiddleware.Driver {
			case apidef.OttoDriver:
				logger.Info("----> Checking security policy: JS Plugin")
				authArray = append(authArray, gw.createMiddleware(&DynamicMiddleware{
					BaseMiddleware:      baseMid,
					MiddlewareClassName: mwAuthCheckFunc.Name,
					Pre:                 true,
					Auth:                true,
				}))
			case apidef.GoPluginDriver:
				gw.mwAppendEnabled(
					&authArray,
					&GoPluginMiddleware{
						BaseMiddleware: baseMid,
						Path:           mwAuthCheckFunc.Path,
						SymbolName:     mwAuthCheckFunc.Name,
						APILevel:       true,
					},
				)
			default:
				coprocessLog.Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

				newExtractor(spec, baseMid)
				gw.mwAppendEnabled(&authArray, &CoProcessMiddleware{baseMid, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver, mwAuthCheckFunc.RawBodyOnly, nil})
			}
		}

		if spec.UseStandardAuth || len(authArray) == 0 {
			logger.Info("Checking security policy: Token")
			authArray = append(authArray, gw.createMiddleware(&AuthKey{baseMid}))
		}

		chainArray = append(chainArray, authArray...)

		for _, obj := range mwPostAuthCheckFuncs {
			if mwDriver == apidef.GoPluginDriver {
				gw.mwAppendEnabled(
					&chainArray,
					&GoPluginMiddleware{
						BaseMiddleware: baseMid,
						Path:           obj.Path,
						SymbolName:     obj.Name,
						APILevel:       true,
					},
				)
			} else {
				coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				gw.mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver, obj.RawBodyOnly, nil})
			}
		}

		gw.mwAppendEnabled(&chainArray, &StripAuth{baseMid})
		gw.mwAppendEnabled(&chainArray, &KeyExpired{baseMid})
		gw.mwAppendEnabled(&chainArray, &AccessRightsCheck{baseMid})
		gw.mwAppendEnabled(&chainArray, &GranularAccessMiddleware{baseMid})
		gw.mwAppendEnabled(&chainArray, &RateLimitAndQuotaCheck{baseMid})
	}

	gw.mwAppendEnabled(&chainArray, &RateLimitForAPI{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &GraphQLMiddleware{BaseMiddleware: baseMid})
	if !spec.UseKeylessAccess {
		gw.mwAppendEnabled(&chainArray, &GraphQLComplexityMiddleware{BaseMiddleware: baseMid})
		gw.mwAppendEnabled(&chainArray, &GraphQLGranularAccessMiddleware{BaseMiddleware: baseMid})
	}

	gw.mwAppendEnabled(&chainArray, &ValidateJSON{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &ValidateRequest{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &PersistGraphQLOperationMiddleware{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &TransformMiddleware{baseMid})
	gw.mwAppendEnabled(&chainArray, &TransformJQMiddleware{baseMid})
	gw.mwAppendEnabled(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &TransformMethod{BaseMiddleware: baseMid})

	// Earliest we can respond with cache get 200 ok
	gw.mwAppendEnabled(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, store: &cacheStore})

	gw.mwAppendEnabled(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &RequestSigning{BaseMiddleware: baseMid})
	gw.mwAppendEnabled(&chainArray, &GoPluginMiddleware{BaseMiddleware: baseMid})

	for _, obj := range mwPostFuncs {
		if mwDriver == apidef.GoPluginDriver {
			gw.mwAppendEnabled(
				&chainArray,
				&GoPluginMiddleware{
					BaseMiddleware: baseMid,
					Path:           obj.Path,
					SymbolName:     obj.Name,
					APILevel:       true,
				},
			)
		} else if mwDriver != apidef.OttoDriver {
			coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
			gw.mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver, obj.RawBodyOnly, nil})
		} else {
			chainArray = append(chainArray, gw.createDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
		}
	}

	chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}, Gw: gw})

	if !spec.UseKeylessAccess {
		var simpleArray []alice.Constructor
		gw.mwAppendEnabled(&simpleArray, &IPWhiteListMiddleware{baseMid})
		gw.mwAppendEnabled(&simpleArray, &IPBlackListMiddleware{BaseMiddleware: baseMid})
		gw.mwAppendEnabled(&simpleArray, &OrganizationMonitor{BaseMiddleware: baseMid, mon: Monitor{Gw: gw}})
		gw.mwAppendEnabled(&simpleArray, &VersionCheck{BaseMiddleware: baseMid})
		simpleArray = append(simpleArray, authArray...)
		gw.mwAppendEnabled(&simpleArray, &KeyExpired{baseMid})
		gw.mwAppendEnabled(&simpleArray, &AccessRightsCheck{baseMid})

		rateLimitPath := path.Join(spec.Proxy.ListenPath, rateLimitEndpoint)
		logger.Debug("Rate limit endpoint is: ", rateLimitPath)

		chainDef.RateLimitChain = alice.New(simpleArray...).
			Then(http.HandlerFunc(userRatesCheck))
	}

	logger.Debug("Setting Listen Path: ", spec.Proxy.ListenPath)

	if trace.IsEnabled() {
		chainDef.ThisHandler = trace.Handle(spec.Name, chain)
	} else {
		chainDef.ThisHandler = chain
	}

	if spec.APIDefinition.AnalyticsPlugin.Enabled {

		ap := &GoAnalyticsPlugin{
			Path:     spec.AnalyticsPlugin.PluginPath,
			FuncName: spec.AnalyticsPlugin.FuncName,
		}

		if ap.loadAnalyticsPlugin() {
			spec.AnalyticsPluginConfig = ap
			logger.Debug("Loaded analytics plugin")
		}
	}

	logger.WithFields(logrus.Fields{
		"prefix":      "gateway",
		"user_ip":     "--",
		"server_name": "--",
		"user_id":     "--",
	}).Info("API Loaded")

	return &chainDef
}

// Check for recursion
const defaultLoopLevelLimit = 5

func isLoop(r *http.Request) (bool, error) {
	if r.URL.Scheme != "tyk" {
		return false, nil
	}

	limit := ctxLoopLevelLimit(r)
	if limit == 0 {
		limit = defaultLoopLevelLimit
	}

	if ctxLoopLevel(r) > limit {
		return true, fmt.Errorf("Loop level too deep. Found more than %d loops in single request", limit)
	}

	return true, nil
}

type DummyProxyHandler struct {
	SH SuccessHandler
	Gw *Gateway `json:"-"`
}

func (d *DummyProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if newURL := ctxGetURLRewriteTarget(r); newURL != nil {
		r.URL = newURL
		ctxSetURLRewriteTarget(r, nil)
	}
	if newMethod := ctxGetTransformRequestMethod(r); newMethod != "" {
		r.Method = newMethod
		ctxSetTransformRequestMethod(r, "")
	}
	if found, err := isLoop(r); found {
		if err != nil {
			handler := ErrorHandler{*d.SH.Base()}
			handler.HandleError(w, r, err.Error(), http.StatusInternalServerError, true)
			return
		}

		r.URL.Scheme = "http"
		if methodOverride := r.URL.Query().Get("method"); methodOverride != "" {
			r.Method = methodOverride
		}

		var handler http.Handler
		if r.URL.Hostname() == "self" {
			if h, found := d.Gw.apisHandlesByID.Load(d.SH.Spec.APIID); found {
				if chain, ok := h.(*ChainObject); ok {
					handler = chain.ThisHandler
				} else {
					log.WithFields(logrus.Fields{"api_id": d.SH.Spec.APIID}).Debug("failed to cast stored api handles to *ChainObject")
				}
			}
		} else {
			ctxSetVersionInfo(r, nil)

			if targetAPI := d.Gw.fuzzyFindAPI(r.URL.Hostname()); targetAPI != nil {
				if h, found := d.Gw.apisHandlesByID.Load(targetAPI.APIID); found {
					if chain, ok := h.(*ChainObject); ok {
						handler = chain.ThisHandler
					} else {
						log.WithFields(logrus.Fields{"api_id": d.SH.Spec.APIID}).Debug("failed to cast stored api handles to *ChainObject")
					}
				}
			} else {
				handler := ErrorHandler{*d.SH.Base()}
				handler.HandleError(w, r, "Can't detect loop target", http.StatusInternalServerError, true)
				return
			}
		}

		// No need to handle errors, in all error cases limit will be set to 0
		loopLevelLimit, _ := strconv.Atoi(r.URL.Query().Get("loop_limit"))
		ctxSetCheckLoopLimits(r, r.URL.Query().Get("check_limits") == "true")

		if origURL := ctxGetOrigRequestURL(r); origURL != nil {
			r.URL.Host = origURL.Host
			r.URL.RawQuery = origURL.RawQuery
			ctxSetOrigRequestURL(r, nil)
		}

		ctxIncLoopLevel(r, loopLevelLimit)
		handler.ServeHTTP(w, r)
		return
	}

	if d.SH.Spec.target.Scheme == "tyk" {
		handler, _, found := d.Gw.findInternalHttpHandlerByNameOrID(d.SH.Spec.target.Host)
		if !found {
			handler := ErrorHandler{*d.SH.Base()}
			handler.HandleError(w, r, "Couldn't detect target", http.StatusInternalServerError, true)
			return
		}

		d.SH.Spec.SanitizeProxyPaths(r)
		ctxSetVersionInfo(r, nil)
		handler.ServeHTTP(w, r)
		return
	}

	d.SH.ServeHTTP(w, r)
}

func (gw *Gateway) findInternalHttpHandlerByNameOrID(apiNameOrID string) (handler http.Handler, targetAPI *APISpec, ok bool) {
	targetAPI = gw.fuzzyFindAPI(apiNameOrID)
	if targetAPI == nil {
		return
	}

	h, found := gw.apisHandlesByID.Load(targetAPI.APIID)
	if !found {
		return nil, nil, false
	}

	return h.(*ChainObject).ThisHandler, targetAPI, true
}

func (gw *Gateway) loadGlobalApps() {
	// we need to make a full copy of the slice, as loadApps will
	// use in-place to sort the apis.
	gw.apisMu.RLock()
	specs := make([]*APISpec, len(gw.apiSpecs))
	copy(specs, gw.apiSpecs)
	gw.apisMu.RUnlock()
	gw.loadApps(specs)
}

func trimCategories(name string) string {
	if i := strings.Index(name, "#"); i != -1 {
		return name[:i-1]
	}

	return name
}

func APILoopingName(name string) string {
	return replaceNonAlphaNumeric(trimCategories(name))
}

func (gw *Gateway) fuzzyFindAPI(search string) *APISpec {
	if search == "" {
		return nil
	}

	gw.apisMu.RLock()
	defer gw.apisMu.RUnlock()

	for _, api := range gw.apisByID {
		if api.APIID == search ||
			api.Id.Hex() == search ||
			strings.EqualFold(APILoopingName(api.Name), search) {

			return api
		}
	}

	return nil
}

type explicitRouteHandler struct {
	prefix  string
	handler http.Handler
	muxer   *proxyMux
}

func (h *explicitRouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == h.prefix || strings.HasPrefix(r.URL.Path, h.prefix+"/") {
		h.handler.ServeHTTP(w, r)
		return
	}
	h.muxer.handle404(w, r)
}

func explicitRouteSubpaths(prefix string, handler http.Handler, muxer *proxyMux, enabled bool) http.Handler {
	// feature is enabled via config option
	if !enabled {
		return handler
	}

	// keep trailing slash paths as-is
	if strings.HasSuffix(prefix, "/") {
		return handler
	}
	// keep paths with params as-is
	if strings.Contains(prefix, "{") && strings.Contains(prefix, "}") {
		return handler
	}

	return &explicitRouteHandler{
		prefix:  prefix,
		handler: handler,
		muxer:   muxer,
	}
}

// loadHTTPService has two responsibilities:
//
// - register gorilla/mux routing handless with proxyMux directly (wrapped),
// - return a raw http.Handler for tyk://ID urls.
func (gw *Gateway) loadHTTPService(spec *APISpec, apisByListen map[string]int, gs *generalStores, muxer *proxyMux) *ChainObject {
	gwConfig := gw.GetConfig()
	port := gwConfig.ListenPort
	if spec.ListenPort != 0 {
		port = spec.ListenPort
	}
	router := muxer.router(port, spec.Protocol, gwConfig)
	if router == nil {
		router = mux.NewRouter()
		muxer.setRouter(port, spec.Protocol, router, gwConfig)
	}

	hostname := gwConfig.HostName
	if gwConfig.EnableCustomDomains && spec.Domain != "" {
		hostname = spec.GetAPIDomain()
	}

	if hostname != "" {
		mainLog.Info("API hostname set: ", hostname)
		router = router.Host(hostname).Subrouter()
	}

	subrouter := router.PathPrefix(spec.Proxy.ListenPath).Subrouter()

	var chainObj *ChainObject

	if curSpec := gw.getApiSpec(spec.APIID); !shouldReloadSpec(curSpec, spec) {
		if chain, found := gw.apisHandlesByID.Load(spec.APIID); found {
			chainObj = chain.(*ChainObject)
		}
	} else {
		chainObj = gw.processSpec(spec, apisByListen, gs, logrus.NewEntry(log))
	}

	gw.generateSubRoutes(spec, subrouter, logrus.NewEntry(log))
	handleCORS(subrouter, spec)

	if chainObj.Skip {
		return chainObj
	}

	if !chainObj.Open {
		subrouter.Handle(rateLimitEndpoint, chainObj.RateLimitChain)
	}

	httpHandler := explicitRouteSubpaths(spec.Proxy.ListenPath, chainObj.ThisHandler, muxer, gwConfig.HttpServerOptions.EnableStrictRoutes)
	subrouter.NewRoute().Handler(httpHandler)

	return chainObj
}

func (gw *Gateway) loadTCPService(spec *APISpec, gs *generalStores, muxer *proxyMux) {
	// Initialise the auth and session managers (use Redis for now)
	authStore := gs.redisStore
	orgStore := gs.redisOrgStore
	switch spec.AuthProvider.StorageEngine {
	case LDAPStorageEngine:
		storageEngine := LDAPStorageHandler{}
		storageEngine.LoadConfFromMeta(spec.AuthProvider.Meta)
		authStore = &storageEngine
	case RPCStorageEngine:
		authStore = gs.rpcAuthStore
		orgStore = gs.rpcOrgStore
		spec.GlobalConfig.EnforceOrgDataAge = true
		gwConfig := gw.GetConfig()
		gwConfig.EnforceOrgDataAge = true
		gw.SetConfig(gwConfig)
	}

	sessionStore := gs.redisStore
	switch spec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = gs.rpcAuthStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis storage pool
	spec.Init(authStore, sessionStore, gs.healthStore, orgStore)

	muxer.addTCPService(spec, nil, gw)
}

type generalStores struct {
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore storage.Handler
}

var playgroundTemplate *template.Template

func (gw *Gateway) readGraphqlPlaygroundTemplate() {
	playgroundPath := filepath.Join(gw.GetConfig().TemplatePath, "playground")
	files, err := ioutil.ReadDir(playgroundPath)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "playground",
		}).Error("Could not load the default playground templates: ", err)
	}

	var paths []string
	for _, file := range files {
		paths = append(paths, filepath.Join(playgroundPath, file.Name()))
	}

	playgroundTemplate, err = template.ParseFiles(paths...)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "playground",
		}).Error("Could not parse the default playground templates: ", err)
	}
}

const (
	playgroundJSTemplateName   = "playground.js"
	playgroundHTMLTemplateName = "index.html"
)

func (gw *Gateway) loadGraphQLPlayground(spec *APISpec, subrouter *mux.Router) {
	// endpoint is a graphql server url to which a playground makes the request.

	endpoint := spec.Proxy.ListenPath
	playgroundPath := path.Join("/", spec.GraphQL.GraphQLPlayground.Path)

	// If tyk-cloud is enabled, listen path will be api id and slug is mapped to listen path in nginx config.
	// So, requests should be sent to slug endpoint, nginx will route them to internal gateway's listen path.
	if gw.GetConfig().Cloud {
		endpoint = fmt.Sprintf("/%s/", spec.Slug)
	}

	subrouter.Methods(http.MethodGet).Path(path.Join(playgroundPath, playgroundJSTemplateName)).HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if playgroundTemplate == nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := playgroundTemplate.ExecuteTemplate(rw, playgroundJSTemplateName, nil); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
		}
	})

	subrouter.Methods(http.MethodGet).Path(playgroundPath).HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if playgroundTemplate == nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		err := playgroundTemplate.ExecuteTemplate(rw, playgroundHTMLTemplateName, struct {
			Url, Schema, PathPrefix string
		}{endpoint, strconv.Quote(spec.GraphQL.Schema), path.Join(endpoint, playgroundPath)})

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
		}
	})
}

// Create the individual API (app) specs based on live configurations and assign middleware
func (gw *Gateway) loadApps(specs []*APISpec) {
	mainLog.Info("Loading API configurations.")

	tmpSpecRegister := make(map[string]*APISpec)
	tmpSpecHandles := new(sync.Map)

	// sort by listen path from longer to shorter, so that /foo
	// doesn't break /foo-bar
	sort.Slice(specs, func(i, j int) bool {
		return len(specs[i].Proxy.ListenPath) > len(specs[j].Proxy.ListenPath)
	})

	// Create a new handler for each API spec
	apisByListen := countApisByListenHash(specs)

	gwConf := gw.GetConfig()
	port := gwConf.ListenPort

	if gwConf.ControlAPIPort != 0 {
		port = gwConf.ControlAPIPort
	}

	muxer := &proxyMux{
		track404Logs: gwConf.Track404Logs,
	}
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(muxer.handle404)
	gw.loadControlAPIEndpoints(router)

	muxer.setRouter(port, "", router, gw.GetConfig())

	gs := gw.prepareStorage()
	shouldTrace := trace.IsEnabled()

	for _, spec := range specs {
		func() {
			defer func() {
				// recover from panic if one occurred. Set err to nil otherwise.
				if err := recover(); err != nil {
					log.Errorf("Panic while loading an API: %v, panic: %v, stacktrace: %v", spec.APIDefinition, err, string(debug.Stack()))
				}
			}()

			if spec.ListenPort != spec.GlobalConfig.ListenPort {
				mainLog.Info("API bind on custom port:", spec.ListenPort)
			}

			if converted, err := gw.kvStore(spec.Proxy.ListenPath); err == nil {
				spec.Proxy.ListenPath = converted
			}

			if currSpec := gw.getApiSpec(spec.APIID); !shouldReloadSpec(currSpec, spec) {
				tmpSpecRegister[spec.APIID] = currSpec
			} else {
				tmpSpecRegister[spec.APIID] = spec
			}

			switch spec.Protocol {
			case "", "http", "https", "h2c":
				if shouldTrace {
					// opentracing works only with http services.
					err := trace.AddTracer("", spec.Name)
					if err != nil {
						mainLog.Errorf("Failed to initialize tracer for %q error:%v", spec.Name, err)
					} else {
						mainLog.Infof("Intialized tracer  api_name=%q", spec.Name)
					}
				}
				tmpSpecHandles.Store(spec.APIID, gw.loadHTTPService(spec, apisByListen, &gs, muxer))
			case "tcp", "tls":
				gw.loadTCPService(spec, &gs, muxer)
			}

			// Set versions free to update links below
			spec.VersionDefinition.BaseID = ""
		}()
	}

	gw.DefaultProxyMux.swap(muxer, gw)

	gw.apisMu.Lock()

	for _, spec := range specs {
		curSpec, ok := gw.apisByID[spec.APIID]
		if ok && curSpec.Checksum != spec.Checksum {
			curSpec.Release()
		}

		// Bind versions to base APIs again
		for _, vID := range spec.VersionDefinition.Versions {
			if versionAPI, ok := tmpSpecRegister[vID]; ok {
				versionAPI.VersionDefinition.BaseID = spec.APIID
			}
		}
	}

	gw.apisByID = tmpSpecRegister
	gw.apisHandlesByID = tmpSpecHandles

	gw.apisMu.Unlock()

	mainLog.Debug("Checker host list")

	// Kick off our host checkers
	if !gw.GetConfig().UptimeTests.Disable {
		gw.SetCheckerHostList()
	}

	mainLog.Debug("Checker host Done")

	mainLog.Info("Initialised API Definitions")

}
