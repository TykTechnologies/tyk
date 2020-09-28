package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jensneuse/graphql-go-tools/pkg/playground"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/coprocess"
	"github.com/TykTechnologies/tyk/v3/storage"
	"github.com/TykTechnologies/tyk/v3/trace"
)

type ChainObject struct {
	Domain         string
	ListenOn       string
	ThisHandler    http.Handler
	RateLimitChain http.Handler
	RateLimitPath  string
	Open           bool
	Index          int
	Skip           bool
	Subrouter      *mux.Router
}

func prepareStorage() generalStores {
	var gs generalStores
	gs.redisStore = &storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: config.Global().HashKeys}
	gs.redisOrgStore = &storage.RedisCluster{KeyPrefix: "orgkey."}
	gs.healthStore = &storage.RedisCluster{KeyPrefix: "apihealth."}
	gs.rpcAuthStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.Global().HashKeys}
	gs.rpcOrgStore = &RPCStorageHandler{KeyPrefix: "orgkey."}
	GlobalSessionManager.Init(gs.redisStore)
	return gs
}

func skipSpecBecauseInvalid(spec *APISpec, logger *logrus.Entry) bool {

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

	if val, err := kvStore(spec.Proxy.TargetURL); err == nil {
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
		domainHash := generateDomainPath(spec.Domain, spec.Proxy.ListenPath)
		if count[domainHash] == 0 {
			dN := spec.Domain
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

func processSpec(spec *APISpec, apisByListen map[string]int,
	gs *generalStores, subrouter *mux.Router, logger *logrus.Entry) *ChainObject {

	var chainDef ChainObject
	chainDef.Subrouter = subrouter

	logger = logger.WithFields(logrus.Fields{
		"org_id":   spec.OrgID,
		"api_id":   spec.APIID,
		"api_name": spec.Name,
	})

	var coprocessLog = logger.WithFields(logrus.Fields{
		"prefix": "coprocess",
	})

	if len(spec.TagHeaders) > 0 {
		// Ensure all headers marked for tagging are lowercase
		lowerCaseHeaders := make([]string, len(spec.TagHeaders))
		for i, k := range spec.TagHeaders {
			lowerCaseHeaders[i] = strings.ToLower(k)

		}
		spec.TagHeaders = lowerCaseHeaders
	}

	if skipSpecBecauseInvalid(spec, logger) {
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
		hash := generateDomainPath(spec.Domain, spec.Proxy.ListenPath)

		if apisByListen[hash] < 2 {
			// not a duplicate
			break
		}
		if !pathModified {
			prev := getApiSpec(spec.APIID)
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
		globalConf := config.Global()
		globalConf.EnforceOrgDataAge = true
		config.SetGlobal(globalConf)
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
	if spec.CustomMiddlewareBundle != "" {
		if err := loadBundle(spec); err != nil {
			logger.WithError(err).Error("Couldn't load bundle")
		}
		prefix = getBundleDestPath(spec)
	}

	logger.Debug("Initializing API")
	var mwPaths []string

	mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwResponseFuncs, mwDriver = loadCustomMiddleware(spec)
	if config.Global().EnableJSVM && mwDriver == apidef.OttoDriver {
		spec.JSVM.LoadJSPaths(mwPaths, prefix)
	}

	//  if bundle was used - fix paths for goplugin-type custom middle-wares
	if mwDriver == apidef.GoPluginDriver && prefix != "" {
		mwAuthCheckFunc.Path = filepath.Join(prefix, mwAuthCheckFunc.Path)
		fixFuncPath(prefix, mwPreFuncs)
		fixFuncPath(prefix, mwPostFuncs)
		fixFuncPath(prefix, mwPostAuthCheckFuncs)
		// TODO: add mwResponseFuncs here when Golang response custom MW support implemented
	}

	if spec.GraphQL.GraphQLPlayground.Enabled {
		loadGraphQLPlayground(spec, subrouter)
	}

	if spec.EnableBatchRequestSupport {
		addBatchEndpoint(spec, subrouter)
	}

	if spec.UseOauth2 {
		logger.Debug("Loading OAuth Manager")
		oauthManager := addOAuthHandlers(spec, subrouter)
		logger.Debug("-- Added OAuth Handlers")

		spec.OAuthManager = oauthManager
		logger.Debug("Done loading OAuth Manager")
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
		proxy = NewMultiTargetProxy(spec, logger)
	} else {
		proxy = TykNewSingleHostReverseProxy(spec.target, spec, logger)
	}

	// Create the response processors, pass all the loaded custom middleware response functions:
	createResponseMiddlewareChain(spec, mwResponseFuncs)

	baseMid := BaseMiddleware{Spec: spec, Proxy: proxy, logger: logger}

	for _, v := range baseMid.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			baseMid.Spec.CircuitBreakerEnabled = true
		}
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			baseMid.Spec.EnforcedTimeoutEnabled = true
		}
	}

	keyPrefix := "cache-" + spec.APIID
	cacheStore := storage.RedisCluster{KeyPrefix: keyPrefix, IsCache: true}
	cacheStore.Connect()

	var chain http.Handler
	var chainArray []alice.Constructor
	var authArray []alice.Constructor

	if spec.UseKeylessAccess {
		chainDef.Open = true
		logger.Info("Checking security policy: Open")
	}

	handleCORS(&chainArray, spec)

	for _, obj := range mwPreFuncs {
		if mwDriver == apidef.GoPluginDriver {
			mwAppendEnabled(
				&chainArray,
				&GoPluginMiddleware{
					BaseMiddleware: baseMid,
					Path:           obj.Path,
					SymbolName:     obj.Name,
				},
			)
		} else if mwDriver != apidef.OttoDriver {
			coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
			mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver, obj.RawBodyOnly, nil})
		} else {
			chainArray = append(chainArray, createDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
		}
	}

	mwAppendEnabled(&chainArray, &VersionCheck{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &IPBlackListMiddleware{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &CertificateCheckMW{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &RequestSizeLimitMiddleware{baseMid})
	mwAppendEnabled(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &TrackEndpointMiddleware{baseMid})
	mwAppendEnabled(&chainArray, &GraphQLMiddleware{BaseMiddleware: baseMid})

	if !spec.UseKeylessAccess {
		// Select the keying method to use for setting session states
		if mwAppendEnabled(&authArray, &Oauth2KeyExists{baseMid}) {
			logger.Info("Checking security policy: OAuth")
		}

		if mwAppendEnabled(&authArray, &BasicAuthKeyIsValid{baseMid, nil, nil}) {
			logger.Info("Checking security policy: Basic")
		}

		if mwAppendEnabled(&authArray, &HTTPSignatureValidationMiddleware{BaseMiddleware: baseMid}) {
			logger.Info("Checking security policy: HMAC")
		}

		if mwAppendEnabled(&authArray, &JWTMiddleware{baseMid}) {
			logger.Info("Checking security policy: JWT")
		}

		if mwAppendEnabled(&authArray, &OpenIDMW{BaseMiddleware: baseMid}) {
			logger.Info("Checking security policy: OpenID")
		}

		coprocessAuth := mwDriver != apidef.OttoDriver && spec.EnableCoProcessAuth
		ottoAuth := !coprocessAuth && mwDriver == apidef.OttoDriver && spec.EnableCoProcessAuth
		gopluginAuth := !coprocessAuth && !ottoAuth && mwDriver == apidef.GoPluginDriver && spec.UseGoPluginAuth

		if coprocessAuth {
			// TODO: check if mwAuthCheckFunc is available/valid
			coprocessLog.Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

			newExtractor(spec, baseMid)
			mwAppendEnabled(&authArray, &CoProcessMiddleware{baseMid, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver, mwAuthCheckFunc.RawBodyOnly, nil})
		}

		if ottoAuth {
			logger.Info("----> Checking security policy: JS Plugin")

			authArray = append(authArray, createDynamicMiddleware(mwAuthCheckFunc.Name, true, false, baseMid))
		}

		if gopluginAuth {
			mwAppendEnabled(
				&authArray,
				&GoPluginMiddleware{
					BaseMiddleware: baseMid,
					Path:           mwAuthCheckFunc.Path,
					SymbolName:     mwAuthCheckFunc.Name,
				},
			)
		}

		if spec.UseStandardAuth || len(authArray) == 0 {
			logger.Info("Checking security policy: Token")
			authArray = append(authArray, createMiddleware(&AuthKey{baseMid}))
		}

		chainArray = append(chainArray, authArray...)

		for _, obj := range mwPostAuthCheckFuncs {
			if mwDriver == apidef.GoPluginDriver {
				mwAppendEnabled(
					&chainArray,
					&GoPluginMiddleware{
						BaseMiddleware: baseMid,
						Path:           obj.Path,
						SymbolName:     obj.Name,
					},
				)
			} else {
				coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver, obj.RawBodyOnly, nil})
			}
		}

		mwAppendEnabled(&chainArray, &StripAuth{baseMid})
		mwAppendEnabled(&chainArray, &KeyExpired{baseMid})
		mwAppendEnabled(&chainArray, &AccessRightsCheck{baseMid})
		mwAppendEnabled(&chainArray, &GranularAccessMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &RateLimitAndQuotaCheck{baseMid})
	}

	mwAppendEnabled(&chainArray, &RateLimitForAPI{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &ValidateJSON{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &TransformMiddleware{baseMid})
	mwAppendEnabled(&chainArray, &TransformJQMiddleware{baseMid})
	mwAppendEnabled(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &TransformMethod{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})
	mwAppendEnabled(&chainArray, &RequestSigning{BaseMiddleware: baseMid})

	for _, obj := range mwPostFuncs {
		if mwDriver == apidef.GoPluginDriver {
			mwAppendEnabled(
				&chainArray,
				&GoPluginMiddleware{
					BaseMiddleware: baseMid,
					Path:           obj.Path,
					SymbolName:     obj.Name,
				},
			)
		} else if mwDriver != apidef.OttoDriver {
			coprocessLog.Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
			mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver, obj.RawBodyOnly, nil})
		} else {
			chainArray = append(chainArray, createDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
		}
	}
	//Do not add middlewares after cache middleware.
	//It will not get executed
	mwAppendEnabled(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: &cacheStore})
	chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

	if !spec.UseKeylessAccess {
		var simpleArray []alice.Constructor
		mwAppendEnabled(&simpleArray, &IPWhiteListMiddleware{baseMid})
		mwAppendEnabled(&simpleArray, &IPBlackListMiddleware{BaseMiddleware: baseMid})
		mwAppendEnabled(&simpleArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		mwAppendEnabled(&simpleArray, &VersionCheck{BaseMiddleware: baseMid})
		simpleArray = append(simpleArray, authArray...)
		mwAppendEnabled(&simpleArray, &KeyExpired{baseMid})
		mwAppendEnabled(&simpleArray, &AccessRightsCheck{baseMid})

		rateLimitPath := spec.Proxy.ListenPath + "tyk/rate-limits/"

		logger.Debug("Rate limit endpoint is: ", rateLimitPath)

		chainDef.RateLimitPath = rateLimitPath
		chainDef.RateLimitChain = alice.New(simpleArray...).
			Then(http.HandlerFunc(userRatesCheck))
	}

	logger.Debug("Setting Listen Path: ", spec.Proxy.ListenPath)

	if trace.IsEnabled() {
		chainDef.ThisHandler = trace.Handle(spec.Name, chain)
	} else {
		chainDef.ThisHandler = chain
	}
	chainDef.ListenOn = spec.Proxy.ListenPath + "{rest:.*}"
	chainDef.Domain = spec.Domain

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
			if h, found := apisHandlesByID.Load(d.SH.Spec.APIID); found {
				handler = h.(http.Handler)
			}
		} else {
			ctxSetVersionInfo(r, nil)

			if targetAPI := fuzzyFindAPI(r.URL.Hostname()); targetAPI != nil {
				if h, found := apisHandlesByID.Load(targetAPI.APIID); found {
					handler = h.(http.Handler)
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
		handler, found := findInternalHttpHandlerByNameOrID(d.SH.Spec.target.Host)
		if !found {
			handler := ErrorHandler{*d.SH.Base()}
			handler.HandleError(w, r, "Couldn't detect target", http.StatusInternalServerError, true)
			return
		}

		sanitizeProxyPaths(d.SH.Spec, r)
		handler.ServeHTTP(w, r)
		return
	}
	d.SH.ServeHTTP(w, r)
}

func findInternalHttpHandlerByNameOrID(apiNameOrID string) (handler http.Handler, ok bool) {
	targetAPI := fuzzyFindAPI(apiNameOrID)
	if targetAPI == nil {
		return nil, false
	}

	h, found := apisHandlesByID.Load(targetAPI.APIID)
	if !found {
		return nil, false
	}

	return h.(http.Handler), true
}

func sanitizeProxyPaths(apiSpec *APISpec, request *http.Request) {
	if !apiSpec.Proxy.StripListenPath {
		return
	}

	request.URL.Path = apiSpec.StripListenPath(request, request.URL.Path)
	request.URL.RawPath = apiSpec.StripListenPath(request, request.URL.RawPath)
}

func loadGlobalApps() {
	// we need to make a full copy of the slice, as loadApps will
	// use in-place to sort the apis.
	apisMu.RLock()
	specs := make([]*APISpec, len(apiSpecs))
	copy(specs, apiSpecs)
	apisMu.RUnlock()
	loadApps(specs)
}

func trimCategories(name string) string {
	if i := strings.Index(name, "#"); i != -1 {
		return name[:i-1]
	}

	return name
}

func fuzzyFindAPI(search string) *APISpec {
	if search == "" {
		return nil
	}

	apisMu.RLock()
	defer apisMu.RUnlock()

	for _, api := range apisByID {
		if api.APIID == search ||
			api.Id.Hex() == search ||
			strings.EqualFold(replaceNonAlphaNumeric(trimCategories(api.Name)), search) {
			return api
		}
	}

	return nil
}

func loadHTTPService(spec *APISpec, apisByListen map[string]int, gs *generalStores, muxer *proxyMux) http.Handler {
	port := config.Global().ListenPort
	if spec.ListenPort != 0 {
		port = spec.ListenPort
	}
	router := muxer.router(port, spec.Protocol)
	if router == nil {
		router = mux.NewRouter()
		muxer.setRouter(port, spec.Protocol, router)
	}

	hostname := config.Global().HostName
	if config.Global().EnableCustomDomains && spec.Domain != "" {
		hostname = spec.Domain
	}

	if hostname != "" {
		mainLog.Info("API hostname set: ", hostname)
		router = router.Host(hostname).Subrouter()
	}

	chainObj := processSpec(spec, apisByListen, gs, router, logrus.NewEntry(log))

	if chainObj.Skip {
		return chainObj.ThisHandler
	}

	if !chainObj.Open {
		router.Handle(chainObj.RateLimitPath, chainObj.RateLimitChain)
	}

	router.Handle(chainObj.ListenOn, chainObj.ThisHandler)

	return chainObj.ThisHandler
}

func loadTCPService(spec *APISpec, gs *generalStores, muxer *proxyMux) {
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
		globalConf := config.Global()
		globalConf.EnforceOrgDataAge = true
		config.SetGlobal(globalConf)
	}

	sessionStore := gs.redisStore
	switch spec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = gs.rpcAuthStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis storage pool
	spec.Init(authStore, sessionStore, gs.healthStore, orgStore)

	muxer.addTCPService(spec, nil)
}

type generalStores struct {
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore storage.Handler
}

func loadGraphQLPlayground(spec *APISpec, router *mux.Router) {
	// endpoint is the endpoint of the url which playground makes request to.
	endpoint := spec.Proxy.ListenPath

	// If tyk-cloud is enabled, listen path will be api id and slug is mapped to listen path in nginx config.
	// So, requests should be sent to slug endpoint, nginx will route them to internal gateway's listen path.
	if config.Global().Cloud {
		endpoint = fmt.Sprintf("/%s/", spec.Slug)
	}

	p := playground.New(playground.Config{
		// PathPrefix is the path on the router where playground handler is loaded.
		PathPrefix:                      spec.Proxy.ListenPath,
		PlaygroundPath:                  spec.GraphQL.GraphQLPlayground.Path,
		GraphqlEndpointPath:             endpoint,
		GraphQLSubscriptionEndpointPath: endpoint,
	})

	handlers, err := p.Handlers()
	if err != nil {
		log.WithError(err).Error("Could not setup graphql playground handlers")
	}

	for _, cfg := range handlers {
		router.HandleFunc(cfg.Path, cfg.Handler)
	}
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(specs []*APISpec) {
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

	globalConf := config.Global()
	port := globalConf.ListenPort

	if globalConf.ControlAPIPort != 0 {
		port = globalConf.ControlAPIPort
	}

	muxer := &proxyMux{}
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(muxer.handle404)
	loadControlAPIEndpoints(router)

	muxer.setRouter(port, "", router)

	gs := prepareStorage()
	shouldTrace := trace.IsEnabled()
	for _, spec := range specs {
		func() {
			defer func() {
				// recover from panic if one occured. Set err to nil otherwise.
				if err := recover(); err != nil {
					log.Errorf("Panic while loading an API: %v, panic: %v, stacktrace: %v", spec.APIDefinition, err, string(debug.Stack()))
				}
			}()

			if spec.ListenPort != spec.GlobalConfig.ListenPort {
				mainLog.Info("API bind on custom port:", spec.ListenPort)
			}

			if converted, err := kvStore(spec.Proxy.ListenPath); err == nil {
				spec.Proxy.ListenPath = converted
			}

			tmpSpecRegister[spec.APIID] = spec

			switch spec.Protocol {
			case "", "http", "https":
				if shouldTrace {
					// opentracing works only with http services.
					err := trace.AddTracer("", spec.Name)
					if err != nil {
						mainLog.Errorf("Failed to initialize tracer for %q error:%v", spec.Name, err)
					} else {
						mainLog.Infof("Intialized tracer  api_name=%q", spec.Name)
					}
				}
				tmpSpecHandles.Store(spec.APIID, loadHTTPService(spec, apisByListen, &gs, muxer))
			case "tcp", "tls":
				loadTCPService(spec, &gs, muxer)
			}
		}()
	}

	defaultProxyMux.swap(muxer)

	// Swap in the new register
	apisMu.Lock()

	// release current specs resources before overwriting map
	for _, curSpec := range apisByID {
		curSpec.Release()
	}

	apisByID = tmpSpecRegister
	apisHandlesByID = tmpSpecHandles

	apisMu.Unlock()

	mainLog.Debug("Checker host list")

	// Kick off our host checkers
	if !config.Global().UptimeTests.Disable {
		SetCheckerHostList()
	}

	mainLog.Debug("Checker host Done")

	mainLog.Info("Initialised API Definitions")
}
