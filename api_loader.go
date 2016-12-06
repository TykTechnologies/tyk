package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tykcommon"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/streamrail/concurrent-map"
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

var ListenPathMap cmap.ConcurrentMap

func prepareStorage() (*RedisClusterStorageManager, *RedisClusterStorageManager, *RedisClusterStorageManager, *RPCStorageHandler, *RPCStorageHandler) {
	redisStore := RedisClusterStorageManager{KeyPrefix: "apikey-", HashKeys: config.HashKeys}
	redisOrgStore := RedisClusterStorageManager{KeyPrefix: "orgkey."}
	healthStore := &RedisClusterStorageManager{KeyPrefix: "apihealth."}
	rpcAuthStore := RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.HashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	rpcOrgStore := RPCStorageHandler{KeyPrefix: "orgkey.", UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}

	FallbackKeySesionManager.Init(&redisStore)

	return &redisStore, &redisOrgStore, healthStore, &rpcAuthStore, &rpcOrgStore
}

func prepareSortOrder(APISpecs *[]*APISpec) {
	sort.Sort(SortableAPISpecListByHost(*APISpecs))
	sort.Sort(SortableAPISpecListByListen(*APISpecs))
}

func skipSpecBecauseInvalid(referenceSpec *APISpec) bool {

	if referenceSpec.Proxy.ListenPath == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.APIDefinition.OrgID,
			"api_id": referenceSpec.APIDefinition.APIID,
		}).Error("Listen path is empty, skipping API ID: ", referenceSpec.APIID)
		return true
	}

	if strings.Contains(referenceSpec.Proxy.ListenPath, " ") {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.APIDefinition.OrgID,
			"api_id": referenceSpec.APIDefinition.APIID,
		}).Error("Listen path contains spaces, is invalid, skipping API ID: ", referenceSpec.APIID)
		return true
	}

	_, err := url.Parse(referenceSpec.APIDefinition.Proxy.TargetURL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": referenceSpec.APIDefinition.OrgID,
			"api_id": referenceSpec.APIDefinition.APIID,
		}).Error("Couldn't parse target URL: ", err)
		return true
	}

	domainHash := generateDomainPath(referenceSpec.Domain, referenceSpec.Proxy.ListenPath)
	val, listenPathExists := ListenPathMap.Get(domainHash)
	if listenPathExists {
		if val.(int) > 1 {
			log.WithFields(logrus.Fields{
				"prefix": "main",
				"org_id": referenceSpec.APIDefinition.OrgID,
				"api_id": referenceSpec.APIDefinition.APIID,
			}).Error("Listen path is a duplicate: ", domainHash)
			return true
		}
	}

	return false
}

func generateDomainPath(hostname string, listenPath string) string {
	return hostname + listenPath
}

func generateListenPathMap(APISpecs *[]*APISpec) {
	// We must track the hostname no matter what
	for _, referenceSpec := range *APISpecs {
		domainHash := generateDomainPath(referenceSpec.Domain, referenceSpec.Proxy.ListenPath)
		val, ok := ListenPathMap.Get(domainHash)
		if ok {
			thisVal := val.(int)
			thisVal++
			ListenPathMap.Set(domainHash, thisVal)
		} else {
			ListenPathMap.Set(domainHash, 1)
			dN := referenceSpec.Domain
			if dN == "" {
				dN = "(no host)"
			}
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
				"domain":   dN,
			}).Info("Tracking hostname")

		}
	}
}

func processSpec(referenceSpec *APISpec,
	Muxer *mux.Router,
	index int,
	redisStore *RedisClusterStorageManager,
	redisOrgStore *RedisClusterStorageManager,
	healthStore *RedisClusterStorageManager,
	rpcAuthStore *RPCStorageHandler,
	rpcOrgStore *RPCStorageHandler,
	subrouter *mux.Router) *ChainObject {

	var thisChainDefinition = ChainObject{}
	thisChainDefinition.Subrouter = subrouter

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": referenceSpec.APIDefinition.Name,
	}).Info("Loading API")

	if skipSpecBecauseInvalid(referenceSpec) {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Warning("Skipped!")
		thisChainDefinition.Skip = true
		return &thisChainDefinition
	}

	// Set up LB targets:
	if referenceSpec.Proxy.EnableLoadBalancing {
		thisSL := tykcommon.NewHostListFromList(referenceSpec.Proxy.Targets)
		referenceSpec.Proxy.StructuredTargetList = *thisSL
	}

	// Initialise the auth and session managers (use Redis for now)
	var authStore StorageHandler
	var sessionStore StorageHandler
	var orgStore StorageHandler

	authStorageEngineToUse := referenceSpec.AuthProvider.StorageEngine
	// if config.SlaveOptions.OverrideDefinitionStorageSettings {
	// 	authStorageEngineToUse = RPCStorageEngine
	// }

	switch authStorageEngineToUse {
	case DefaultStorageEngine:
		authStore = redisStore
		orgStore = redisOrgStore
	case LDAPStorageEngine:
		thisStorageEngine := LDAPStorageHandler{}
		thisStorageEngine.LoadConfFromMeta(referenceSpec.AuthProvider.Meta)
		authStore = &thisStorageEngine
		orgStore = redisOrgStore
	case RPCStorageEngine:
		thisStorageEngine := rpcAuthStore // &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.HashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
		authStore = thisStorageEngine
		orgStore = rpcOrgStore // &RPCStorageHandler{KeyPrefix: "orgkey.", UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
		config.EnforceOrgDataAge = true

	default:
		authStore = redisStore
		orgStore = redisOrgStore
	}

	SessionStorageEngineToUse := referenceSpec.SessionProvider.StorageEngine
	// if config.SlaveOptions.OverrideDefinitionStorageSettings {
	// 	SessionStorageEngineToUse = RPCStorageEngine
	// }

	switch SessionStorageEngineToUse {
	case DefaultStorageEngine:
		sessionStore = redisStore

	case RPCStorageEngine:
		sessionStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.HashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	default:
		sessionStore = redisStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis sotorage pool
	referenceSpec.Init(authStore, sessionStore, healthStore, orgStore)

	//Set up all the JSVM middleware
	mwPaths := []string{}
	var mwAuthCheckFunc tykcommon.MiddlewareDefinition
	mwPreFuncs := []tykcommon.MiddlewareDefinition{}
	mwPostFuncs := []tykcommon.MiddlewareDefinition{}
	mwPostAuthCheckFuncs := []tykcommon.MiddlewareDefinition{}

	var mwDriver tykcommon.MiddlewareDriver

	if EnableCoProcess {
		loadBundle(referenceSpec)
	}

	// TODO: use config.EnableCoProcess
	if config.EnableJSVM || EnableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Debug("Loading Middleware")

		mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwDriver = loadCustomMiddleware(referenceSpec)

		if config.EnableJSVM && mwDriver == tykcommon.OttoDriver {
			var pathPrefix string
			if referenceSpec.CustomMiddlewareBundle != "" {
				pathPrefix = strings.Join([]string{referenceSpec.APIID, referenceSpec.CustomMiddlewareBundle}, "-")
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
			thisOauthManager := addOAuthHandlers(referenceSpec, subrouter, false)
			log.Debug("-- Added OAuth Handlers")

			referenceSpec.OAuthManager = thisOauthManager
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
	remote, _ := url.Parse(referenceSpec.APIDefinition.Proxy.TargetURL)

	referenceSpec.target = remote
	var proxy ReturningHttpHandler
	if enableVersionOverrides {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Info("Multi target enabled")
		proxy = &MultiTargetProxy{}
	} else {
		proxy = TykNewSingleHostReverseProxy(remote, referenceSpec)
	}

	// initialise the proxy
	proxy.New(nil, referenceSpec)

	// Create the response processors
	creeateResponseMiddlewareChain(referenceSpec)

	//proxyHandler := http.HandlerFunc(ProxyHandler(proxy, referenceSpec))
	tykMiddleware := &TykMiddleware{referenceSpec, proxy}
	CheckCBEnabled(tykMiddleware)
	CheckETEnabled(tykMiddleware)

	keyPrefix := "cache-" + referenceSpec.APIDefinition.APIID
	CacheStore := &RedisClusterStorageManager{KeyPrefix: keyPrefix, IsCache: true}
	CacheStore.Connect()

	var chain http.Handler

	if referenceSpec.APIDefinition.UseKeylessAccess {
		thisChainDefinition.Open = true
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Info("Checking security policy: Open")

		// Add pre-process MW
		var chainArray = []alice.Constructor{}
		handleCORS(&chainArray, referenceSpec)

		var baseChainArray = []alice.Constructor{}
		AppendMiddleware(&baseChainArray, &RateCheckMW{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &IPWhiteListMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &MiddlewareContextVars{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &RequestSizeLimitMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &TrackEndpointMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &TransformMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &TransformHeaders{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &RedisCacheMiddleware{TykMiddleware: tykMiddleware, CacheStore: CacheStore}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &VirtualEndpoint{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &URLRewriteMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray, &TransformMethod{TykMiddleware: tykMiddleware}, tykMiddleware)

		log.Debug(referenceSpec.APIDefinition.Name, " - CHAIN SIZE: ", len(baseChainArray))

		for _, obj := range mwPreFuncs {
			if mwDriver != tykcommon.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.APIDefinition.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_Pre, obj.Name, mwDriver}, tykMiddleware)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, tykMiddleware))
			}
		}

		for _, baseMw := range baseChainArray {
			chainArray = append(chainArray, baseMw)
		}

		for _, obj := range mwPostFuncs {
			if mwDriver != tykcommon.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.APIDefinition.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_Post, obj.Name, mwDriver}, tykMiddleware)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, tykMiddleware))
			}
		}

		// for KeyLessAccess we can't support rate limiting, versioning or access rules
		chain = alice.New(chainArray...).Then(DummyProxyHandler{SH: SuccessHandler{tykMiddleware}})

	} else {

		var chainArray = []alice.Constructor{}

		handleCORS(&chainArray, referenceSpec)

		var baseChainArray_PreAuth = []alice.Constructor{}
		AppendMiddleware(&baseChainArray_PreAuth, &RateCheckMW{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &IPWhiteListMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &RequestSizeLimitMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &MiddlewareContextVars{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PreAuth, &TrackEndpointMiddleware{tykMiddleware}, tykMiddleware)

		// Add pre-process MW
		for _, obj := range mwPreFuncs {
			if mwDriver != tykcommon.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.APIDefinition.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_Pre, obj.Name, mwDriver}, tykMiddleware)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, tykMiddleware))
			}
		}

		for _, baseMw := range baseChainArray_PreAuth {
			chainArray = append(chainArray, baseMw)
		}

		// Select the keying method to use for setting session states
		var authArray = []alice.Constructor{}
		if referenceSpec.APIDefinition.UseOauth2 {
			// Oauth2
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: OAuth")
			authArray = append(authArray, CreateMiddleware(&Oauth2KeyExists{tykMiddleware}, tykMiddleware))

		}

		useCoProcessAuth := EnableCoProcess && mwDriver != tykcommon.OttoDriver && referenceSpec.EnableCoProcessAuth

		var useOttoAuth bool = false
		if !useCoProcessAuth {
			useOttoAuth = mwDriver == tykcommon.OttoDriver && referenceSpec.EnableCoProcessAuth
		}

		if referenceSpec.APIDefinition.UseBasicAuth {
			// Basic Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: Basic")
			authArray = append(authArray, CreateMiddleware(&BasicAuthKeyIsValid{tykMiddleware}, tykMiddleware))
		}

		if referenceSpec.EnableSignatureChecking {
			// HMAC Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: HMAC")
			authArray = append(authArray, CreateMiddleware(&HMACMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware))
		}

		if referenceSpec.EnableJWT {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: JWT")
			authArray = append(authArray, CreateMiddleware(&JWTMiddleware{tykMiddleware}, tykMiddleware))
		}

		if referenceSpec.UseOpenID {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: OpenID")

			// initialise the OID configuration on this reference Spec
			authArray = append(authArray, CreateMiddleware(&OpenIDMW{TykMiddleware: tykMiddleware}, tykMiddleware))
		}

		if useCoProcessAuth {
			// TODO: check if mwAuthCheckFunc is available/valid
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: CoProcess Plugin")

			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

			if useCoProcessAuth {
				newExtractor(referenceSpec, tykMiddleware)
				AppendMiddleware(&authArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver}, tykMiddleware)
			}
		}

		if useOttoAuth {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Checking security policy: JS Plugin")

			authArray = append(authArray, CreateDynamicAuthMiddleware(mwAuthCheckFunc.Name, tykMiddleware))
		}

		if referenceSpec.UseStandardAuth || (!referenceSpec.UseOpenID && !referenceSpec.EnableJWT && !referenceSpec.EnableSignatureChecking && !referenceSpec.APIDefinition.UseBasicAuth && !referenceSpec.APIDefinition.UseOauth2 && !useCoProcessAuth && !useOttoAuth) {
			// Auth key
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Info("Checking security policy: Token")
			authArray = append(authArray, CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware))
		}

		for _, authMw := range authArray {
			chainArray = append(chainArray, authMw)
		}

		for _, obj := range mwPostAuthCheckFuncs {
			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": referenceSpec.APIDefinition.Name,
			}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
			AppendMiddleware(&chainArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver}, tykMiddleware)
		}

		var baseChainArray_PostAuth = []alice.Constructor{}
		AppendMiddleware(&baseChainArray_PostAuth, &KeyExpired{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &AccessRightsCheck{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &GranularAccessMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformMiddleware{tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformHeaders{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &URLRewriteMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &RedisCacheMiddleware{TykMiddleware: tykMiddleware, CacheStore: CacheStore}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &TransformMethod{TykMiddleware: tykMiddleware}, tykMiddleware)
		AppendMiddleware(&baseChainArray_PostAuth, &VirtualEndpoint{TykMiddleware: tykMiddleware}, tykMiddleware)

		for _, baseMw := range baseChainArray_PostAuth {
			chainArray = append(chainArray, baseMw)
		}

		for _, obj := range mwPostFuncs {
			if mwDriver != tykcommon.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": referenceSpec.APIDefinition.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				AppendMiddleware(&chainArray, &CoProcessMiddleware{tykMiddleware, coprocess.HookType_Post, obj.Name, mwDriver}, tykMiddleware)
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, tykMiddleware))
			}
		}

		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Debug("Custom middleware completed processing")

		// Use CreateMiddleware(&ModifiedMiddleware{tykMiddleware}, tykMiddleware)  to run custom middleware
		chain = alice.New(chainArray...).Then(DummyProxyHandler{SH: SuccessHandler{tykMiddleware}})

		log.Debug("Chain completed")

		userCheckHandler := http.HandlerFunc(UserRatesCheck())
		simpleChain_PreAuth := []alice.Constructor{
			CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
			CreateMiddleware(&OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware),
			CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware)}

		simpleChain_PostAuth := []alice.Constructor{
			CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
			CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware)}

		var fullSimpleChain = []alice.Constructor{}
		for _, mw := range simpleChain_PreAuth {
			fullSimpleChain = append(fullSimpleChain, mw)
		}

		for _, authMw := range authArray {
			fullSimpleChain = append(fullSimpleChain, authMw)
		}

		for _, mw := range simpleChain_PostAuth {
			fullSimpleChain = append(fullSimpleChain, mw)
		}

		simpleChain := alice.New(fullSimpleChain...).Then(userCheckHandler)

		rateLimitPath := fmt.Sprintf("%s%s", referenceSpec.Proxy.ListenPath, "tyk/rate-limits/")
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": referenceSpec.APIDefinition.Name,
		}).Debug("Rate limit endpoint is: ", rateLimitPath)
		//subrouter.Handle(rateLimitPath, simpleChain)
		thisChainDefinition.RateLimitPath = rateLimitPath
		thisChainDefinition.RateLimitChain = simpleChain
	}

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": referenceSpec.APIDefinition.Name,
	}).Debug("Setting Listen Path: ", referenceSpec.Proxy.ListenPath)
	//subrouter.Handle(referenceSpec.Proxy.ListenPath+"{rest:.*}", chain)

	thisChainDefinition.ThisHandler = chain
	thisChainDefinition.ListenOn = referenceSpec.Proxy.ListenPath + "{rest:.*}"

	notifyAPILoaded(referenceSpec)

	return &thisChainDefinition
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(APISpecs *[]*APISpec, Muxer *mux.Router) {
	ListenPathMap = cmap.New()
	// load the APi defs
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading API configurations.")

	var tempSpecRegister = make(map[string]*APISpec)

	// Only create this once, add other types here as needed, seems wasteful but we can let the GC handle it
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore := prepareStorage()

	prepareSortOrder(APISpecs)

	chainChannel := make(chan *ChainObject)
	var wg sync.WaitGroup

	wg.Add(len(*APISpecs))
	// Create a new handler for each API spec
	loadList := make([]*ChainObject, len(*APISpecs))
	generateListenPathMap(APISpecs)
	for i, referenceSpec := range *APISpecs {
		var subrouter *mux.Router

		go func(chChan chan *ChainObject, referenceSpec *APISpec, i int, subrouter *mux.Router) {
			defer wg.Done()
			// Handle custom domains
			if config.EnableCustomDomains {
				if referenceSpec.Domain != "" {
					log.WithFields(logrus.Fields{
						"prefix":   "main",
						"api_name": referenceSpec.APIDefinition.Name,
						"domain":   referenceSpec.Domain,
					}).Info("Custom Domain set.")
					subrouter = mainRouter.Host(referenceSpec.Domain).Subrouter()
				} else {
					subrouter = Muxer
				}
			} else {
				subrouter = Muxer
			}

			thisChainObject := processSpec(referenceSpec, Muxer, i, redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore, subrouter)
			thisChainObject.Index = i
			chChan <- thisChainObject
		}(chainChannel, referenceSpec, i, subrouter)

		// TODO: This will not deal with skipped APis well
		tempSpecRegister[referenceSpec.APIDefinition.APIID] = referenceSpec
	}

	go func() {
		for thisCHObj := range chainChannel {
			loadList[thisCHObj.Index] = thisCHObj
		}
	}()

	wg.Wait()

	time.Sleep(1 * time.Second)

	for _, thisChainObject := range loadList {
		if !thisChainObject.Skip {
			if !thisChainObject.Open {
				thisChainObject.Subrouter.Handle(thisChainObject.RateLimitPath, thisChainObject.RateLimitChain)
			}

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Processed and listening on: ", thisChainObject.ListenOn)
			thisChainObject.Subrouter.Handle(thisChainObject.ListenOn, thisChainObject.ThisHandler)
		}
	}

	// All APIs processed, now we can healthcheck
	// Add a root message to check all is OK
	Muxer.HandleFunc("/hello", pingTest)

	// Swap in the new register
	ApiSpecRegister = &tempSpecRegister

	log.Debug("Checker host list")

	// Kick off our host checkers
	if config.UptimeTests.Disable == false {
		SetCheckerHostList()
	}

	log.Debug("Checker host Done")

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialised API Definitions")

	if config.SlaveOptions.UseRPC {
		//log.Warning("TODO: PUT THE KEEPALIVE WATCHER BACK")
		StartRPCKeepaliveWatcher(rpcAuthStore)
		StartRPCKeepaliveWatcher(rpcOrgStore)
	}

}
