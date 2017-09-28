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
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/storage"
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

func prepareStorage() (storage.RedisCluster, storage.RedisCluster, storage.RedisCluster, *RPCStorageHandler, *RPCStorageHandler) {
	redisStore := storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: config.Global.HashKeys}
	redisOrgStore := storage.RedisCluster{KeyPrefix: "orgkey."}
	healthStore := storage.RedisCluster{KeyPrefix: "apihealth."}
	rpcAuthStore := RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.Global.HashKeys, UserKey: config.Global.SlaveOptions.APIKey, Address: config.Global.SlaveOptions.ConnectionString}
	rpcOrgStore := RPCStorageHandler{KeyPrefix: "orgkey.", UserKey: config.Global.SlaveOptions.APIKey, Address: config.Global.SlaveOptions.ConnectionString}

	FallbackKeySesionManager.Init(&redisStore)

	return redisStore, redisOrgStore, healthStore, &rpcAuthStore, &rpcOrgStore
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
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
				"domain":   dN,
			}).Info("Tracking hostname")
		}
		count[domainHash]++
	}
	return count
}

func processSpec(spec *APISpec, apisByListen map[string]int,
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore storage.Handler,
	subrouter *mux.Router) *ChainObject {

	var chainDef ChainObject
	chainDef.Subrouter = subrouter

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": spec.Name,
	}).Info("Loading API")

	if len(spec.TagHeaders) > 0 {
		// Ensure all headers marked for tagging are lowercase
		lowerCaseHeaders := make([]string, len(spec.TagHeaders))
		for i, k := range spec.TagHeaders {
			lowerCaseHeaders[i] = strings.ToLower(k)

		}
		spec.TagHeaders = lowerCaseHeaders
	}

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
	authStore := redisStore
	orgStore := redisOrgStore
	switch spec.AuthProvider.StorageEngine {
	case LDAPStorageEngine:
		storageEngine := LDAPStorageHandler{}
		storageEngine.LoadConfFromMeta(spec.AuthProvider.Meta)
		authStore = &storageEngine
	case RPCStorageEngine:
		authStore = rpcAuthStore
		orgStore = rpcOrgStore
		config.Global.EnforceOrgDataAge = true
	}

	sessionStore := redisStore
	switch spec.SessionProvider.StorageEngine {
	case RPCStorageEngine:
		sessionStore = rpcAuthStore
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

	// TODO: use config.Global.EnableCoProcess
	if config.Global.EnableJSVM || EnableCoProcess {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Loading Middleware")

		var mwPaths []string
		mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostAuthCheckFuncs, mwDriver = loadCustomMiddleware(spec)

		if config.Global.EnableJSVM && mwDriver == apidef.OttoDriver {
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
	spec.target, _ = url.Parse(spec.Proxy.TargetURL)

	var proxy ReturningHttpHandler
	if enableVersionOverrides {
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Info("Multi target enabled")
		proxy = NewMultiTargetProxy(spec)
	} else {
		proxy = TykNewSingleHostReverseProxy(spec.target, spec)
	}

	// Create the response processors
	creeateResponseMiddlewareChain(spec)

	baseMid := BaseMiddleware{spec, proxy}
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
				mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, createDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		mwAppendEnabled(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &CertificateCheckMW{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RateLimitForAPI{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &ValidateJSON{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &VersionCheck{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RequestSizeLimitMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &TrackEndpointMiddleware{baseMid})

		mwAppendEnabled(&chainArray, &TransformMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore})
		mwAppendEnabled(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &TransformMethod{BaseMiddleware: baseMid})

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, createDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		// for KeyLessAccess we can't support rate limiting, versioning or access rules
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

	} else {
		var chainArray []alice.Constructor
		var authArray []alice.Constructor

		handleCORS(&chainArray, spec)

		// Add pre-process MW
		for _, obj := range mwPreFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Pre", ", driver: ", mwDriver)
				mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Pre, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, createDynamicMiddleware(obj.Name, true, obj.RequireSession, baseMid))
			}
		}

		mwAppendEnabled(&chainArray, &RateCheckMW{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &IPWhiteListMiddleware{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &CertificateCheckMW{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &VersionCheck{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RequestSizeLimitMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &MiddlewareContextVars{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &TrackEndpointMiddleware{baseMid})

		// Select the keying method to use for setting session states
		if mwAppendEnabled(&authArray, &Oauth2KeyExists{baseMid}) {
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: OAuth")
		}

		if mwAppendEnabled(&authArray, &BasicAuthKeyIsValid{baseMid}) {
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: Basic")
		}

		if mwAppendEnabled(&authArray, &HMACMiddleware{BaseMiddleware: baseMid}) {
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: HMAC")
		}

		if mwAppendEnabled(&authArray, &JWTMiddleware{baseMid}) {
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: JWT")
		}

		if mwAppendEnabled(&authArray, &OpenIDMW{BaseMiddleware: baseMid}) {
			log.WithFields(logrus.Fields{
				"prefix":   "main",
				"api_name": spec.Name,
			}).Info("Checking security policy: OpenID")
		}

		coprocessAuth := EnableCoProcess && mwDriver != apidef.OttoDriver && spec.EnableCoProcessAuth
		ottoAuth := !coprocessAuth && mwDriver == apidef.OttoDriver && spec.EnableCoProcessAuth

		if coprocessAuth {
			// TODO: check if mwAuthCheckFunc is available/valid
			log.WithFields(logrus.Fields{
				"prefix":   "coprocess",
				"api_name": spec.Name,
			}).Debug("Registering coprocess middleware, hook name: ", mwAuthCheckFunc.Name, "hook type: CustomKeyCheck", ", driver: ", mwDriver)

			newExtractor(spec, baseMid)
			mwAppendEnabled(&authArray, &CoProcessMiddleware{baseMid, coprocess.HookType_CustomKeyCheck, mwAuthCheckFunc.Name, mwDriver})
		}

		if ottoAuth {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Checking security policy: JS Plugin")

			authArray = append(authArray, createDynamicMiddleware(mwAuthCheckFunc.Name, true, false, baseMid))
		}

		if spec.UseStandardAuth || len(authArray) == 0 {
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
			mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_PostKeyAuth, obj.Name, mwDriver})
		}

		mwAppendEnabled(&chainArray, &StripAuth{baseMid})
		mwAppendEnabled(&chainArray, &KeyExpired{baseMid})
		mwAppendEnabled(&chainArray, &AccessRightsCheck{baseMid})
		mwAppendEnabled(&chainArray, &RateLimitForAPI{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RateLimitAndQuotaCheck{baseMid})
		mwAppendEnabled(&chainArray, &GranularAccessMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &ValidateJSON{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &TransformMiddleware{baseMid})
		mwAppendEnabled(&chainArray, &TransformHeaders{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &URLRewriteMiddleware{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &RedisCacheMiddleware{BaseMiddleware: baseMid, CacheStore: cacheStore})
		mwAppendEnabled(&chainArray, &TransformMethod{BaseMiddleware: baseMid})
		mwAppendEnabled(&chainArray, &VirtualEndpoint{BaseMiddleware: baseMid})

		for _, obj := range mwPostFuncs {
			if mwDriver != apidef.OttoDriver {
				log.WithFields(logrus.Fields{
					"prefix":   "coprocess",
					"api_name": spec.Name,
				}).Debug("Registering coprocess middleware, hook name: ", obj.Name, "hook type: Post", ", driver: ", mwDriver)
				mwAppendEnabled(&chainArray, &CoProcessMiddleware{baseMid, coprocess.HookType_Post, obj.Name, mwDriver})
			} else {
				chainArray = append(chainArray, createDynamicMiddleware(obj.Name, false, obj.RequireSession, baseMid))
			}
		}

		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Custom middleware completed processing")

		// Use createMiddleware(&ModifiedMiddleware{baseMid})  to run custom middleware
		chain = alice.New(chainArray...).Then(&DummyProxyHandler{SH: SuccessHandler{baseMid}})

		log.Debug("Chain completed")

		var simpleArray []alice.Constructor
		mwAppendEnabled(&simpleArray, &IPWhiteListMiddleware{baseMid})
		mwAppendEnabled(&simpleArray, &OrganizationMonitor{BaseMiddleware: baseMid})
		mwAppendEnabled(&simpleArray, &VersionCheck{BaseMiddleware: baseMid})
		simpleArray = append(simpleArray, authArray...)
		mwAppendEnabled(&simpleArray, &KeyExpired{baseMid})
		mwAppendEnabled(&simpleArray, &AccessRightsCheck{baseMid})

		rateLimitPath := spec.Proxy.ListenPath + "tyk/rate-limits/"
		log.WithFields(logrus.Fields{
			"prefix":   "main",
			"api_name": spec.Name,
		}).Debug("Rate limit endpoint is: ", rateLimitPath)
		chainDef.RateLimitPath = rateLimitPath
		chainDef.RateLimitChain = alice.New(simpleArray...).
			Then(http.HandlerFunc(userRatesCheck))
	}

	log.WithFields(logrus.Fields{
		"prefix":   "main",
		"api_name": spec.Name,
	}).Debug("Setting Listen Path: ", spec.Proxy.ListenPath)

	chainDef.ThisHandler = chain
	chainDef.ListenOn = spec.Proxy.ListenPath + "{rest:.*}"

	if config.Global.UseRedisLog {
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

func loadGlobalApps(router *mux.Router) {
	// we need to make a full copy of the slice, as loadApps will
	// use in-place to sort the apis.
	apisMu.RLock()
	specs := make([]*APISpec, len(apiSpecs))
	copy(specs, apiSpecs)
	apisMu.RUnlock()
	loadApps(specs, router)

	if config.Global.NewRelic.AppName != "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Adding NewRelic instrumentation")
		AddNewRelicInstrumentation(NewRelicApplication, router)
	}
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(specs []*APISpec, muxer *mux.Router) {
	hostname := config.Global.HostName
	if hostname != "" {
		muxer = muxer.Host(hostname).Subrouter()
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("API hostname set: ", hostname)
	}
	// load the APi defs
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading API configurations.")

	tmpSpecRegister := make(map[string]*APISpec)

	// Only create this once, add other types here as needed, seems wasteful but we can let the GC handle it
	redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore := prepareStorage()

	// sort by listen path from longer to shorter, so that /foo
	// doesn't break /foo-bar
	sort.Slice(specs, func(i, j int) bool {
		return len(specs[i].Proxy.ListenPath) > len(specs[j].Proxy.ListenPath)
	})

	chainChannel := make(chan *ChainObject)

	// Create a new handler for each API spec
	loadList := make([]*ChainObject, len(specs))
	apisByListen := countApisByListenHash(specs)

	// Set up the host sub-routers first, since we need to set up
	// exactly one per host. If we set up one per API definition,
	// only one of the APIs will work properly, since the router
	// doesn't backtrack and will stop at the first host sub-router
	// match.
	hostRouters := map[string]*mux.Router{"": muxer}
	var hosts []string
	for _, spec := range specs {
		hosts = append(hosts, spec.Domain)
	}
	// Decreasing sort by length and chars, so that the order of
	// creation of the host sub-routers is deterministic and
	// consistent with the order of the paths.
	sort.Slice(hosts, func(i, j int) bool {
		h1, h2 := hosts[i], hosts[j]
		if len(h1) != len(h2) {
			return len(h1) > len(h2)
		}
		return h1 > h2
	})
	for _, host := range hosts {
		if !config.Global.EnableCustomDomains {
			continue // disabled
		}
		if hostRouters[host] != nil {
			continue // already set up a subrouter
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"domain": host,
		}).Info("Sub-router created for domain")
		hostRouters[host] = muxer.Host(host).Subrouter()
	}

	for i, spec := range specs {
		go func(spec *APISpec, i int) {
			subrouter := hostRouters[spec.Domain]
			if subrouter == nil {
				log.WithFields(logrus.Fields{
					"prefix": "main",
					"domain": spec.Domain,
					"api_id": spec.APIID,
				}).Warning("Trying to load API with Domain when custom domains are disabled.")
				subrouter = muxer
			}

			chainObj := processSpec(spec, apisByListen, redisStore, redisOrgStore, healthStore, rpcAuthStore, rpcOrgStore, subrouter)
			chainObj.Index = i
			chainChannel <- chainObj
		}(spec, i)

		// TODO: This will not deal with skipped APis well
		tmpSpecRegister[spec.APIID] = spec
	}

	for range specs {
		chObj := <-chainChannel
		loadList[chObj.Index] = chObj
	}

	for _, chainObj := range loadList {
		if chainObj.Skip {
			continue
		}
		if !chainObj.Open {
			chainObj.Subrouter.Handle(chainObj.RateLimitPath, chainObj.RateLimitChain)
		}

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Processed and listening on: ", chainObj.ListenOn)
		chainObj.Subrouter.Handle(chainObj.ListenOn, chainObj.ThisHandler)
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
	if !config.Global.UptimeTests.Disable {
		SetCheckerHostList()
	}

	log.Debug("Checker host Done")

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialised API Definitions")

	if config.Global.SlaveOptions.UseRPC {
		//log.Warning("TODO: PUT THE KEEPALIVE WATCHER BACK")
		startRPCKeepaliveWatcher(rpcAuthStore)
		startRPCKeepaliveWatcher(rpcOrgStore)
	}
}
