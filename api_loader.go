package main

import (
	"fmt"
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

func skipSpecBecauseInvalid(spec *APISpec) bool {

	if spec.Proxy.ListenPath == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": spec.OrgID,
			"api_id": spec.APIID,
		}).Error("Listen path is empty, skipping API ID: ", spec.APIID)
		return true
	}

	if strings.Contains(spec.Proxy.ListenPath, " ") {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": spec.OrgID,
			"api_id": spec.APIID,
		}).Error("Listen path contains spaces, is invalid, skipping API ID: ", spec.APIID)
		return true
	}

	_, err := url.Parse(spec.Proxy.TargetURL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": spec.OrgID,
			"api_id": spec.APIID,
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
	for _, spec := range apiSpecs {
		domainHash := generateDomainPath(spec.Domain, spec.Proxy.ListenPath)
		count := apiCountByListenHash[domainHash]
		apiCountByListenHash[domainHash]++
		if count == 0 {
			dN := spec.Domain
			if dN == "" {
				dN = "(no host)"
			}
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
				"domain":   dN,
			}).Info("Tracking hostname")
		}
	}
}

func processSpec(spec *APISpec,
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore StorageHandler,
	subrouter *mux.Router) *ChainObject {

	var chainDef ChainObject
	chainDef.Subrouter = subrouter

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": spec.Name,
	}).Info("Loading API")

	if skipSpecBecauseInvalid(spec) {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Warning("Skipped!")
		chainDef.Skip = true
		return &chainDef
	}

	pathModified := false
	for {
		hash := generateDomainPath(spec.Domain, spec.Proxy.ListenPath)
		if apiCountByListenHash[hash] < 2 {
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
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"org_id": spec.OrgID,
			"api_id": spec.APIID,
		}).Error("Listen path collision, changed to ", spec.Proxy.ListenPath)
	}

	// Set up LB targets:
	if spec.Proxy.EnableLoadBalancing {
		sl := apidef.NewHostListFromList(spec.Proxy.Targets)
		spec.Proxy.StructuredTargetList = sl
	}

	// Initialise the auth and session managers (use Redis for now)
	var authStore, sessionStore, orgStore StorageHandler

	switch spec.AuthProvider.StorageEngine {
	case LDAPStorageEngine:
		storageEngine := LDAPStorageHandler{}
		storageEngine.LoadConfFromMeta(spec.AuthProvider.Meta)
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

	switch spec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: globalConf.HashKeys, UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}
	default:
		sessionStore = redisStore
	}

	// Health checkers are initialised per spec so that each API handler has it's own connection and redis sotorage pool
	spec.Init(authStore, sessionStore, healthStore, orgStore)

	//Set up all the JSVM middleware
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostAuthCheckFuncs := []apidef.MiddlewareDefinition{}

	var mwDriver apidef.MiddlewareDriver

	if EnableCoProcess {
		loadBundle(spec)
	}

	// TODO: use globalConf.EnableCoProcess
	if globalConf.EnableJSVM || EnableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Loading Middleware")

		var mwPaths []string
		mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwDriver = loadCustomMiddleware(spec)

		if globalConf.EnableJSVM && mwDriver == apidef.OttoDriver {
			var pathPrefix string
			if spec.CustomMiddlewareBundle != "" {
				pathPrefix = spec.APIID + "-" + spec.CustomMiddlewareBundle
			}
			spec.JSVM.LoadJSPaths(mwPaths, pathPrefix)
		}
	}

	if spec.EnableBatchRequestSupport {
		addBatchEndpoint(spec, subrouter)
	}

	if spec.UseOauth2 {
		log.Debug("Loading OAuth Manager")
		if !rpcEmergencyMode {
			oauthManager := addOAuthHandlers(spec, subrouter)
			log.Debug("-- Added OAuth Handlers")

			spec.OAuthManager = oauthManager
			log.Debug("Done loading OAuth Manager")
		} else {
			log.Warning("RPC Emergency mode detected! OAuth APIs will not function!")
		}
	}

	enableVersionOverrides := false
	for _, versionData := range spec.VersionData.Versions {
		if versionData.OverrideTarget != "" {
			enableVersionOverrides = true
			break
		}
	}

	// Already vetted
	remote, _ := url.Parse(spec.Proxy.TargetURL)

	spec.target = remote
	var proxy ReturningHttpHandler
	if enableVersionOverrides {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Info("Multi target enabled")
		proxy = NewMultiTargetProxy(spec)
	} else {
		proxy = TykNewSingleHostReverseProxy(remote, spec)
	}

	// Create the response processors
	creeateResponseMiddlewareChain(spec)

	baseMid := &BaseMiddleware{spec, proxy}
	CheckCBEnabled(baseMid)
	CheckETEnabled(baseMid)

	keyPrefix := "cache-" + spec.APIID
	cacheStore := &RedisClusterStorageManager{KeyPrefix: keyPrefix, IsCache: true}
	cacheStore.Connect()

	var chain http.Handler

	if spec.UseKeylessAccess {
		chainDef.Open = true
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Info("Checking security policy: Open")

		// Add pre-process MW
		chainArray := []alice.Constructor{}
		handleCORS(&chainArray, spec)

		for _, obj := range mwPreFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				appendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		appendMiddleware(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &VersionCheck{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &RequestSizeLimitMiddleware{baseMid})
		appendMiddleware(&chainArray, &TrackEndpointMiddleware{baseMid})
		appendMiddleware(&chainArray, &TransformMiddleware{baseMid})
		appendMiddleware(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore})
		appendMiddleware(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &TransformMethod{BaseMiddleware: baseMid})

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				appendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		// for KeyLessAccess we can't support rate limiting, versioning or access rules
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

	} else {

		var chainArray []alice.Constructor

		handleCORS(&chainArray, spec)

		// Add pre-process MW
		for _, obj := range mwPreFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				appendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		appendMiddleware(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &VersionCheck{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &RequestSizeLimitMiddleware{baseMid})
		appendMiddleware(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &TrackEndpointMiddleware{baseMid})

		// Select the keying method to use for setting session states
		var authArray []alice.Constructor
		if spec.UseOauth2 {
			// Oauth2
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: OAuth")
			authArray = append(authArray, createMiddleware(&Oauth2KeyExists{baseMid}))

		}

		useCoProcessAuth := EnableCoProcess && mwDriver != apidef.OttoDriver && spec.EnableCoProcessAuth

		useOttoAuth := false
		if !useCoProcessAuth {
			useOttoAuth = mwDriver == apidef.OttoDriver && spec.EnableCoProcessAuth
		}

		if spec.UseBasicAuth {
			// Basic Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: Basic")
			authArray = append(authArray, createMiddleware(&BasicAuthKeyIsValid{baseMid}))
		}

		if spec.EnableSignatureChecking {
			// HMAC Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: HMAC")
			authArray = append(authArray, createMiddleware(&HMACMiddleware{BaseMiddleware: baseMid}))
		}

		if spec.EnableJWT {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: JWT")
			authArray = append(authArray, createMiddleware(&JWTMiddleware{baseMid}))
		}

		if spec.UseOpenID {
			// JWT Auth
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: OpenID")

			// initialise the OID configuration on this reference Spec
			authArray = append(authArray, createMiddleware(&OpenIDMW{BaseMiddleware: baseMid}))
		}

		if useCoProcessAuth {
			// TODO: check if mwAuthCheckFunc is available/valid
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: CoProcess Plugin")

			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": spec.Name,
			}).Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

			if useCoProcessAuth {
				newExtractor(spec, baseMid)
				appendMiddleware(&authArray, &CoProcessMiddleware{baseMid, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver})
			}
		}

		if useOttoAuth {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Checking security policy: JS Plugin")

			authArray = append(authArray, CreateDynamicAuthMiddleware(mwAuthCheckFunc.Name, baseMid))
		}

		if spec.UseStandardAuth || (!spec.UseOpenID && !spec.EnableJWT && !spec.EnableSignatureChecking && !spec.UseBasicAuth && !spec.UseOauth2 && !useCoProcessAuth && !useOttoAuth) {
			// Auth key
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: Token")
			authArray = append(authArray, createMiddleware(&AuthKey{baseMid}))
		}

		chainArray = append(chainArray, authArray...)

		for _, obj := range mwPostAuthCheckFuncs {
			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": spec.Name,
			}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
			appendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver})
		}

		appendMiddleware(&chainArray, &KeyExpired{baseMid})
		appendMiddleware(&chainArray, &AccessRightsCheck{baseMid})
		appendMiddleware(&chainArray, &RateLimitAndQuotaCheck{baseMid})
		appendMiddleware(&chainArray, &GranularAccessMiddleware{baseMid})
		appendMiddleware(&chainArray, &TransformMiddleware{baseMid})
		appendMiddleware(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore})
		appendMiddleware(&chainArray, &TransformMethod{BaseMiddleware: baseMid})
		appendMiddleware(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				appendMiddleware(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Custom middleware completed processing")

		// Use createMiddleware(&ModifiedMiddleware{baseMid})  to run custom middleware
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

		log.Debug("Chain completed")

		userCheckHandler := UserRatesCheck()
		simpleChain_PreAuth := []alice.Constructor{
			createMiddleware(&IPWhiteListMiddleware{baseMid}),
			createMiddleware(&OrganizationMonitor{BaseMiddleware: baseMid}),
			createMiddleware(&VersionCheck{BaseMiddleware: baseMid})}

		simpleChain_PostAuth := []alice.Constructor{
			createMiddleware(&KeyExpired{baseMid}),
			createMiddleware(&AccessRightsCheck{baseMid})}

		var fullSimpleChain []alice.Constructor
		fullSimpleChain = append(fullSimpleChain, simpleChain_PreAuth...)
		fullSimpleChain = append(fullSimpleChain, authArray...)
		fullSimpleChain = append(fullSimpleChain, simpleChain_PostAuth...)

		simpleChain := alice.New(fullSimpleChain...).Then(userCheckHandler)

		rateLimitPath := spec.Proxy.ListenPath + "tyk/rate-limits/"
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Rate limit endpoint is: ", rateLimitPath)
		//subrouter.Handle(rateLimitPath, simpleChain)
		chainDef.RateLimitPath = rateLimitPath
		chainDef.RateLimitChain = simpleChain
	}

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": spec.Name,
	}).Debug("Setting Listen Path: ", spec.Proxy.ListenPath)
	//subrouter.Handle(spec.Proxy.ListenPath+"{rest:.*}", chain)

	chainDef.ThisHandler = chain
	chainDef.ListenOn = spec.Proxy.ListenPath + "{rest:.*}"

	if globalConf.UseRedisLog {
		log.WithFields(logrus.Fields{
			"prefix":      "gateway",
			"user_ip":     "--",
			"server_name": "--",
			"user_id":     "--",
			"org_id":      spec.OrgID,
			"api_id":      spec.APIID,
		}).Info("Loaded: ", spec.Name)
	}

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

	// sort by listen path from longer to shorter, so that /foo
	// doesn't break /foo-bar
	sort.Slice(apiSpecs, func(i, j int) bool {
		return len(apiSpecs[i].Proxy.ListenPath) > len(apiSpecs[j].Proxy.ListenPath)
	})

	chainChannel := make(chan *ChainObject)

	// Create a new handler for each API spec
	loadList := make([]*ChainObject, len(apiSpecs))
	generateListenPathMap(apiSpecs)
	for i, spec := range apiSpecs {
		go func(spec *APISpec, i int) {
			subrouter := muxer
			// Handle custom domains
			if globalConf.EnableCustomDomains && spec.Domain != "" {
				log.WithFields(logrus.Fields{
					"prefix":   "main",
					"api_name": spec.Name,
					"domain":   spec.Domain,
				}).Info("Custom Domain set.")
				subrouter = mainRouter.Host(spec.Domain).Subrouter()
			}
			chainObj := processSpec(spec, redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore, subrouter)
			chainObj.Index = i
			chainChannel <- chainObj
		}(spec, i)

		// TODO: This will not deal with skipped APis well
		tmpSpecRegister[spec.APIID] = spec
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
	muxer.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello Tiki")
	})

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
