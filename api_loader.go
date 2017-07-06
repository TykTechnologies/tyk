package main

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

type ChainObject struct {
	ListenOn       string
	ThisHandler    http.Handler
	RateLimitChain http.Handler
	RateLimitPath  string
	Open           bool
	Index          int
	Skip           bool
	Subrouter      *mux.Router
}

var apiCountByListenHash map[string]int

func prepareStorage() (*RedisClusterStorageManager, *RedisClusterStorageManager, *RedisClusterStorageManager, *RPCStorageHandler, *RPCStorageHandler) {
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-", HashKeys: globalConf.HashKeys}
	redisOrgStore := RedisClusterStorageManager{KeyPrefix: "orgkey."}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	rpcAuthStore := RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: globalConf.HashKeys, UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}
	rpcOrgStore := RPCStorageHandler{KeyPrefix: "orgkey.", UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}

	FallbackKeySesionManager.Init(&redisStore)

	return &redisStore, &redisOrgStore, healthStore, &rpcAuthStore, &rpcOrgStore
}

func prepareSortOrder(apiSpecs []*APISpec) {
	sort.Sort(SortableAPISpecListByHost(apiSpecs))
	sort.Sort(SortableAPISpecListByListen(apiSpecs))
}

func skipSpecBecauseInvalid(referenceSpec *APISpec) bool {

	if referenceSpec.Proxy.ListenPath == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.OrgID,
			"api_id": referenceSpec.APIID,
		}).Error("Listen path is empty, skipping API ID: ", referenceSpec.APIID)
		return true
	}

	if strings.Contains(referenceSpec.Proxy.ListenPath, " ") {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.OrgID,
			"api_id": referenceSpec.APIID,
		}).Error("Listen path contains spaces, is invalid, skipping API ID: ", referenceSpec.APIID)
		return true
	}

	_, err := url.Parse(referenceSpec.Proxy.TargetURL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.OrgID,
			"api_id": referenceSpec.APIID,
		}).Error("Couldn't parse target URL: ", err)
		return true
	}

	return false
}

func generateDomainPath(hostname, listenPath string) string {
	return hostname + listenPath
}

func generateListenPathMap(apiSpecs []*APISpec) {
	// We must track the hostname no matter what
	for _, referenceSpec := range apiSpecs {
		domainHash := generateDomainPath(referenceSpec.Domain, referenceSpec.Proxy.ListenPath)
		count := apiCountByListenHash[domainHash]
		apiCountByListenHash[domainHash]++
		if count == 0 {
			dN := referenceSpec.Domain
			if dN == "" {
				dN = "(no host)"
			}
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
				"domain":   dN,
			}).Info("Tracking hostname")
		}
	}
}

func processSpec(referenceSpec *APISpec,
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore StorageHandler,
	subrouter *mux.Router) *ChainObject {

	var chainDef ChainObject
	chainDef.Subrouter = subrouter

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": referenceSpec.Name,
	}).Info("Loading API")

	if skipSpecBecauseInvalid(referenceSpec) {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Warning("Skipped!")
		chainDef.Skip = true
		return &chainDef
	}

	pathModified := false
	for {
		hash := generateDomainPath(referenceSpec.Domain, referenceSpec.Proxy.ListenPath)
		if apiCountByListenHash[hash] < 2 {
			// not a duplicate
			break
		}
		if !pathModified {
			prev := getApiSpec(referenceSpec.APIID)
			if prev != nil && prev.Proxy.ListenPath == referenceSpec.Proxy.ListenPath {
				// if this APIID was already loaded and
				// had this listen path, let it keep it.
				break
			}
			referenceSpec.Proxy.ListenPath += "-" + referenceSpec.APIID
			pathModified = true
		} else {
			// keep adding '_' chars
			referenceSpec.Proxy.ListenPath += "_"
		}
	}
	if pathModified {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.OrgID,
			"api_id": referenceSpec.APIID,
		}).Error("Listen path collision, changed to ", referenceSpec.Proxy.ListenPath)
	}

	// Set up LB targets:
	if referenceSpec.Proxy.EnableLoadBalancing {
		sl := apidef.NewHostListFromList(referenceSpec.Proxy.Targets)
		referenceSpec.Proxy.StructuredTargetList = sl
	}

	// Initialise the auth and session managers (use Redis for now)
	var authStore, sessionStore, orgStore StorageHandler

	switch referenceSpec.AuthProvider.StorageEngine {
	case LDAPStorageEngine:
		storageEngine := LDAPStorageHandler{}
		storageEngine.LoadConfFromMeta(referenceSpec.AuthProvider.Meta)
		authStore = &storageEngine
		orgStore = redisOrgStore
	case RPCStorageEngine:
		storageEngine := rpcAuthStore
		authStore = storageEngine
		orgStore = rpcOrgStore
		globalConf.EnforceOrgDataAge = true

	default:
		authStore = redisStore
		orgStore = redisOrgStore
	}

	switch referenceSpec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: globalConf.HashKeys, UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}
	default:
		sessionStore = redisStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis sotorage pool
	referenceSpec.Init(authStore, sessionStore, healthStore, orgStore)

	//Set up all the JSVM middleware
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostAuthCheckFuncs := []apidef.MiddlewareDefinition{}

	var mwDriver apidef.MiddlewareDriver

	if EnableCoProcess {
		loadBundle(referenceSpec)
	}

	// TODO: use globalConf.EnableCoProcess
	if globalConf.EnableJSVM || EnableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Debug("Loading Middleware")

		var mwPaths []string
		mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwDriver = loadCustomMiddleware(referenceSpec)

		if globalConf.EnableJSVM && mwDriver == apidef.OttoDriver {
			var pathPrefix string
			if referenceSpec.CustomMiddlewareBundle != "" {
				pathPrefix = referenceSpec.APIID + "-" + referenceSpec.CustomMiddlewareBundle
			}
			referenceSpec.JSVM.LoadJSPaths(mwPaths, pathPrefix)
		}
	}

	if referenceSpec.EnableBatchRequestSupport {
		addBatchEndpoint(referenceSpec, subrouter)
	}

	if referenceSpec.UseOauth2 {
		log.Debug("Loading OAuth Manager")
		if !RPC_EmergencyMode {
			oauthManager := addOAuthHandlers(referenceSpec, subrouter)
			log.Debug("-- Added OAuth Handlers")

			referenceSpec.OAuthManager = oauthManager
			log.Debug("Done loading OAuth Manager")
		} else {
			log.Warning("RPC Emergency mode detected! OAuth APIs will not function!")
		}
	}

	enableVersionOverrides := false
	for _, versionData := range referenceSpec.VersionData.Versions {
		if versionData.OverrideTarget != "" {
			enableVersionOverrides = true
			break
		}
	}

	// Already vetted
	remote, _ := url.Parse(referenceSpec.Proxy.TargetURL)

	referenceSpec.target = remote
	var proxy ReturningHttpHandler
	if enableVersionOverrides {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Info("Multi target enabled")
		proxy = &MultiTargetProxy{}
	} else {
		proxy = TykNewSingleHostReverseProxy(remote, referenceSpec)
	}

	// initialise the proxy
	proxy.New(nil, referenceSpec)

	// Create the response processors
	creeateResponseMiddlewareChain(referenceSpec)

	baseMid := &BaseMiddleware{referenceSpec, proxy}
	CheckCBEnabled(baseMid)
	CheckETEnabled(baseMid)

	keyPrefix := "cache-" + referenceSpec.APIID
	cacheStore := &RedisClusterStorageManager{KeyPrefix: keyPrefix, IsCache: true}
	cacheStore.Connect()

	var chain http.Handler

	if referenceSpec.UseKeylessAccess {
		chainDef.Open = true
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Info("Checking security policy: Open")

		// Add pre-process MW
		chainArray := []alice.Constructor{}
		handleCORS(&chainArray, referenceSpec)

		baseChainArray := []alice.Constructor{}
		AppendMiddleware(&baseChainArray, &RateCheckMW{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &OrganizationMonitor{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &MiddlewareContextVars{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &VersionCheck{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &RequestSizeLimitMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &TrackEndpointMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &TransformMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &TransformHeaders{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore}, baseMid)
		AppendMiddleware(&baseChainArray, &VirtualEndpoint{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray, &TransformMethod{BaseMiddleware: baseMid}, baseMid)

		log.Debug(referenceSpec.Name, " - CHAIN SIZE: ", len(baseChainArray))

		for _, obj := range mwPreFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver}, baseMid)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		chainArray = append(chainArray, baseChainArray...)

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver}, baseMid)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		// for KeyLessAccess we can't support rate limiting, versioning or access rules
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

	} else {

		var chainArray []alice.Constructor

		handleCORS(&chainArray, referenceSpec)

		var baseChainArray_PreAuth []alice.Constructor
		AppendMiddleware(&baseChainArray_PreAuth, &RateCheckMW{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &IPWhiteListMiddleware{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &OrganizationMonitor{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &VersionCheck{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &RequestSizeLimitMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &MiddlewareContextVars{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PreAuth, &TrackEndpointMiddleware{baseMid}, baseMid)

		// Add pre-process MW
		for _, obj := range mwPreFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver}, baseMid)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		chainArray = append(chainArray, baseChainArray_PreAuth...)

		// Select the keying method to use for setting session states
		var authArray []alice.Constructor
		if referenceSpec.UseOauth2 {
			// Oauth2
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: OAuth")
			authArray = append(authArray, CreateMiddleware(&Oauth2KeyExists{baseMid}, baseMid))

		}

		useCoProcessAuth := EnableCoProcess && mwDriver != apidef.OttoDriver && referenceSpec.EnableCoProcessAuth

		useOttoAuth := false
		if !useCoProcessAuth {
			useOttoAuth = mwDriver == apidef.OttoDriver && referenceSpec.EnableCoProcessAuth
		}

		if referenceSpec.UseBasicAuth {
			// Basic Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: Basic")
			authArray = append(authArray, CreateMiddleware(&BasicAuthKeyIsValid{baseMid}, baseMid))
		}

		if referenceSpec.EnableSignatureChecking {
			// HMAC Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: HMAC")
			authArray = append(authArray, CreateMiddleware(&HMACMiddleware{BaseMiddleware: baseMid}, baseMid))
		}

		if referenceSpec.EnableJWT {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: JWT")
			authArray = append(authArray, CreateMiddleware(&JWTMiddleware{baseMid}, baseMid))
		}

		if referenceSpec.UseOpenID {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: OpenID")

			// initialise the OID configuration on this reference Spec
			authArray = append(authArray, CreateMiddleware(&OpenIDMW{BaseMiddleware: baseMid}, baseMid))
		}

		if useCoProcessAuth {
			// TODO: check if mwAuthCheckFunc is available/valid
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: CoProcess Plugin")

			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": referenceSpec.Name,
			}).Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

			if useCoProcessAuth {
				newExtractor(referenceSpec, baseMid)
				AppendMiddleware(&authArray, &CoProcessMiddleware{baseMid, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver}, baseMid)
			}
		}

		if useOttoAuth {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Checking security policy: JS Plugin")

			authArray = append(authArray, CreateDynamicAuthMiddleware(mwAuthCheckFunc.Name, baseMid))
		}

		if referenceSpec.UseStandardAuth || (!referenceSpec.UseOpenID && !referenceSpec.EnableJWT && !referenceSpec.EnableSignatureChecking && !referenceSpec.UseBasicAuth && !referenceSpec.UseOauth2 && !useCoProcessAuth && !useOttoAuth) {
			// Auth key
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.Name,
			}).Info("Checking security policy: Token")
			authArray = append(authArray, CreateMiddleware(&AuthKey{baseMid}, baseMid))
		}

		chainArray = append(chainArray, authArray...)

		for _, obj := range mwPostAuthCheckFuncs {
			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": referenceSpec.Name,
			}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
			AppendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver}, baseMid)
		}

		var baseChainArray_PostAuth []alice.Constructor
		AppendMiddleware(&baseChainArray_PostAuth, &KeyExpired{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &AccessRightsCheck{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &RateLimitAndQuotaCheck{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &GranularAccessMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformMiddleware{baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformHeaders{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &URLRewriteMiddleware{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformMethod{BaseMiddleware: baseMid}, baseMid)
		AppendMiddleware(&baseChainArray_PostAuth, &VirtualEndpoint{BaseMiddleware: baseMid}, baseMid)

		chainArray = append(chainArray, baseChainArray_PostAuth...)

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver}, baseMid)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Debug("Custom middleware completed processing")

		// Use CreateMiddleware(&ModifiedMiddleware{baseMid}, baseMid)  to run custom middleware
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

		log.Debug("Chain completed")

		userCheckHandler := UserRatesCheck()
		simpleChain_PreAuth := []alice.Constructor{
			CreateMiddleware(&IPWhiteListMiddleware{baseMid}, baseMid),
			CreateMiddleware(&OrganizationMonitor{BaseMiddleware: baseMid}, baseMid),
			CreateMiddleware(&VersionCheck{BaseMiddleware: baseMid}, baseMid)}

		simpleChain_PostAuth := []alice.Constructor{
			CreateMiddleware(&KeyExpired{baseMid}, baseMid),
			CreateMiddleware(&AccessRightsCheck{baseMid}, baseMid)}

		var fullSimpleChain []alice.Constructor
		fullSimpleChain = append(fullSimpleChain, simpleChain_PreAuth...)
		fullSimpleChain = append(fullSimpleChain, authArray...)
		fullSimpleChain = append(fullSimpleChain, simpleChain_PostAuth...)

		simpleChain := alice.New(fullSimpleChain...).Then(userCheckHandler)

		rateLimitPath := referenceSpec.Proxy.ListenPath + "tyk/rate-limits/"
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.Name,
		}).Debug("Rate limit endpoint is: ", rateLimitPath)
		//subrouter.Handle(rateLimitPath, simpleChain)
		chainDef.RateLimitPath = rateLimitPath
		chainDef.RateLimitChain = simpleChain
	}

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": referenceSpec.Name,
	}).Debug("Setting Listen Path: ", referenceSpec.Proxy.ListenPath)
	//subrouter.Handle(referenceSpec.Proxy.ListenPath+"{rest:.*}", chain)

	chainDef.ThisHandler = chain
	chainDef.ListenOn = referenceSpec.Proxy.ListenPath + "{rest:.*}"

	notifyAPILoaded(referenceSpec)

	return &chainDef
}

type DummyProxyHandler struct {
	SH SuccessHandler
}

func (d *DummyProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.SH.ServeHTTP(w, r)
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(apiSpecs []*APISpec, muxer *mux.Router) {
	hostname := globalConf.HostName
	if hostname != "" {
		muxer = muxer.Host(hostname).Subrouter()
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("API hostname set: ", hostname)
	}
	apiCountByListenHash = make(map[string]int, len(apiSpecs))
	// load the APi defs
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading API configurations.")

	tmpSpecRegister := make(map[string]*APISpec)

	// Only create this once, add other types here as needed, seems wasteful but we can let the GC handle it
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore := prepareStorage()

	prepareSortOrder(apiSpecs)

	chainChannel := make(chan *ChainObject)

	// Create a new handler for each API spec
	loadList := make([]*ChainObject, len(apiSpecs))
	generateListenPathMap(apiSpecs)
	for i, referenceSpec := range apiSpecs {
		go func(referenceSpec *APISpec, i int) {
			subrouter := muxer
			// Handle custom domains
			if globalConf.EnableCustomDomains && referenceSpec.Domain != "" {
				log.WithFields(logrus.Fields{
					"prefix":   "main",
					"api_name": referenceSpec.Name,
					"domain":   referenceSpec.Domain,
				}).Info("Custom Domain set.")
				subrouter = mainRouter.Host(referenceSpec.Domain).Subrouter()
			}
			chainObj := processSpec(referenceSpec, redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore, subrouter)
			chainObj.Index = i
			chainChannel <- chainObj
		}(referenceSpec, i)

		// TODO: This will not deal with skipped APis well
		tmpSpecRegister[referenceSpec.APIID] = referenceSpec
	}

	for range apiSpecs {
		chObj := <-chainChannel
		loadList[chObj.Index] = chObj
	}

	for _, chainObj := range loadList {
		if !chainObj.Skip {
			if !chainObj.Open {
				chainObj.Subrouter.Handle(chainObj.RateLimitPath, chainObj.RateLimitChain)
			}

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Processed and listening on: ", chainObj.ListenOn)
			chainObj.Subrouter.Handle(chainObj.ListenOn, chainObj.ThisHandler)
		}
	}

	// All APIs processed, now we can healthcheck
	// Add a root message to check all is OK
	muxer.HandleFunc("/hello", pingTest)

	// Swap in the new register
	apisMu.Lock()
	apisByID = tmpSpecRegister
	apisMu.Unlock()

	log.Debug("Checker host list")

	// Kick off our host checkers
	if !globalConf.UptimeTests.Disable {
		SetCheckerHostList()
	}

	log.Debug("Checker host Done")

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialised API Definitions")

	if globalConf.SlaveOptions.UseRPC {
		//log.Warning("TODO: PUT THE KEEPALIVE WATCHER BACK")
		startRPCKeepaliveWatcher(rpcAuthStore)
		startRPCKeepaliveWatcher(rpcOrgStore)
	}

}
