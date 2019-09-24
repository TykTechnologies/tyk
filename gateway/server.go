package gateway

import (
	"context"
	"html/template"
	"io/ioutil"
	stdlog "log"
	"log/syslog"
	"net"
	"net/http"
	pprof_http "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	logstashHook "github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/evalphobia/logrus_sentry"
	"github.com/facebookgo/pidfile"
	graylogHook "github.com/gemnasium/logrus-graylog-hook"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/lonelycode/osin"
	newrelic "github.com/newrelic/go-agent"
	"github.com/rs/cors"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"rsc.io/letsencrypt"

	"github.com/TykTechnologies/again"
	gas "github.com/TykTechnologies/goautosocket"
	"github.com/TykTechnologies/gorpc"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/checkup"
	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dnscache"
	"github.com/TykTechnologies/tyk/headers"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
)

var (
	log                      = logger.Get()
	mainLog                  = log.WithField("prefix", "main")
	pubSubLog                = log.WithField("prefix", "pub-sub")
	rawLog                   = logger.GetRaw()
	templates                *template.Template
	analytics                RedisAnalyticsHandler
	GlobalEventsJSVM         JSVM
	memProfFile              *os.File
	MainNotifier             RedisNotifier
	DefaultOrgStore          DefaultSessionManager
	DefaultQuotaStore        DefaultSessionManager
	FallbackKeySesionManager = SessionHandler(&DefaultSessionManager{})
	MonitoringHandler        config.TykEventHandler
	RPCListener              RPCStorageHandler
	DashService              DashboardServiceSender
	CertificateManager       *certs.CertificateManager
	NewRelicApplication      newrelic.Application

	apisMu   sync.RWMutex
	apiSpecs []*APISpec
	apisByID = map[string]*APISpec{}

	keyGen DefaultKeyGenerator

	policiesMu   sync.RWMutex
	policiesByID = map[string]user.Policy{}

	LE_MANAGER  letsencrypt.Manager
	LE_FIRSTRUN bool

	muNodeID sync.Mutex // guards NodeID
	NodeID   string

	runningTestsMu sync.RWMutex
	testMode       bool

	// confPaths is the series of paths to try to use as config files. The
	// first one to exist will be used. If none exists, a default config
	// will be written to the first path in the list.
	//
	// When --conf=foo is used, this will be replaced by []string{"foo"}.
	confPaths = []string{
		"tyk.conf",
		// TODO: add ~/.config/tyk/tyk.conf here?
		"/etc/tyk/tyk.conf",
	}

	dnsCacheManager dnscache.IDnsCacheManager
)

const (
	defReadTimeout  = 120 * time.Second
	defWriteTimeout = 120 * time.Second
	appName         = "tyk-gateway"
)

// SetNodeID writes NodeID safely.
func SetNodeID(nodeID string) {
	muNodeID.Lock()
	NodeID = nodeID
	muNodeID.Unlock()
}

// GetNodeID reads NodeID safely.
func GetNodeID() string {
	muNodeID.Lock()
	defer muNodeID.Unlock()
	return NodeID
}

func isRunningTests() bool {
	runningTestsMu.RLock()
	v := testMode
	runningTestsMu.RUnlock()
	return v
}

func setTestMode(v bool) {
	runningTestsMu.Lock()
	testMode = v
	runningTestsMu.Unlock()
}

func getApiSpec(apiID string) *APISpec {
	apisMu.RLock()
	spec := apisByID[apiID]
	apisMu.RUnlock()
	return spec
}

func apisByIDLen() int {
	apisMu.RLock()
	defer apisMu.RUnlock()
	return len(apisByID)
}

var redisPurgeOnce sync.Once
var rpcPurgeOnce sync.Once
var purgeTicker = time.Tick(time.Second)
var rpcPurgeTicker = time.Tick(10 * time.Second)

// Create all globals and init connection handlers
func setupGlobals(ctx context.Context) {

	reloadMu.Lock()
	defer reloadMu.Unlock()

	dnsCacheManager = dnscache.NewDnsCacheManager(config.Global().DnsCache.MultipleIPsHandleStrategy)
	if config.Global().DnsCache.Enabled {
		dnsCacheManager.InitDNSCaching(
			time.Duration(config.Global().DnsCache.TTL)*time.Second,
			time.Duration(config.Global().DnsCache.CheckInterval)*time.Second)
	}

	if config.Global().EnableAnalytics && config.Global().Storage.Type != "redis" {
		mainLog.Fatal("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	// Initialise our Host Checker
	healthCheckStore := storage.RedisCluster{KeyPrefix: "host-checker:"}
	InitHostCheckManager(ctx, &healthCheckStore)

	redisStore := storage.RedisCluster{KeyPrefix: "apikey-", HashKeys: config.Global().HashKeys}
	FallbackKeySesionManager.Init(&redisStore)

	versionStore := storage.RedisCluster{KeyPrefix: "version-check-"}
	versionStore.Connect()
	_ = versionStore.SetKey("gateway", VERSION, 0)

	if config.Global().EnableAnalytics && analytics.Store == nil {
		globalConf := config.Global()
		globalConf.LoadIgnoredIPs()
		config.SetGlobal(globalConf)
		mainLog.Debug("Setting up analytics DB connection")

		analyticsStore := storage.RedisCluster{KeyPrefix: "analytics-"}
		analytics.Store = &analyticsStore
		analytics.Init(globalConf)

		redisPurgeOnce.Do(func() {
			store := storage.RedisCluster{KeyPrefix: "analytics-"}
			redisPurger := RedisPurger{Store: &store}
			go redisPurger.PurgeLoop(purgeTicker)
		})

		if config.Global().AnalyticsConfig.Type == "rpc" {
			mainLog.Debug("Using RPC cache purge")

			rpcPurgeOnce.Do(func() {
				store := storage.RedisCluster{KeyPrefix: "analytics-"}
				purger := rpc.Purger{
					Store: &store,
				}
				purger.Connect()
				go purger.PurgeLoop(rpcPurgeTicker)
			})
		}
		go flushNetworkAnalytics(ctx)
	}

	// Load all the files that have the "error" prefix.
	templatesDir := filepath.Join(config.Global().TemplatePath, "error*")
	templates = template.Must(template.ParseGlob(templatesDir))

	CoProcessInit()

	// Get the notifier ready
	mainLog.Debug("Notifier will not work in hybrid mode")
	mainNotifierStore := &storage.RedisCluster{}
	mainNotifierStore.Connect()
	MainNotifier = RedisNotifier{mainNotifierStore, RedisPubSubChannel}

	if config.Global().Monitor.EnableTriggerMonitors {
		h := &WebHookHandler{}
		if err := h.Init(config.Global().Monitor.Config); err != nil {
			mainLog.Error("Failed to initialise monitor! ", err)
		} else {
			MonitoringHandler = h
		}
	}

	if globalConfig := config.Global(); globalConfig.AnalyticsConfig.NormaliseUrls.Enabled {
		mainLog.Info("Setting up analytics normaliser")
		globalConfig.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()
		config.SetGlobal(globalConfig)
	}

	certificateSecret := config.Global().Secret
	if config.Global().Security.PrivateCertificateEncodingSecret != "" {
		certificateSecret = config.Global().Security.PrivateCertificateEncodingSecret
	}

	CertificateManager = certs.NewCertificateManager(getGlobalStorageHandler("cert-", false), certificateSecret, log)

	if config.Global().NewRelic.AppName != "" {
		NewRelicApplication = SetupNewRelic()
	}
}

func buildConnStr(resource string) string {

	if config.Global().DBAppConfOptions.ConnectionString == "" && config.Global().DisableDashboardZeroConf {
		mainLog.Fatal("Connection string is empty, failing.")
	}

	if !config.Global().DisableDashboardZeroConf && config.Global().DBAppConfOptions.ConnectionString == "" {
		mainLog.Info("Waiting for zeroconf signal...")
		for config.Global().DBAppConfOptions.ConnectionString == "" {
			time.Sleep(1 * time.Second)
		}
	}

	return config.Global().DBAppConfOptions.ConnectionString + resource
}

func syncAPISpecs() (int, error) {
	loader := APIDefinitionLoader{}
	apisMu.Lock()
	defer apisMu.Unlock()
	var s []*APISpec
	if config.Global().UseDBAppConfigs {
		connStr := buildConnStr("/system/apis")
		tmpSpecs, err := loader.FromDashboardService(connStr, config.Global().NodeSecret)
		if err != nil {
			log.Error("failed to load API specs: ", err)
			return 0, err
		}

		s = tmpSpecs

		mainLog.Debug("Downloading API Configurations from Dashboard Service")
	} else if config.Global().SlaveOptions.UseRPC {
		mainLog.Debug("Using RPC Configuration")

		var err error
		s, err = loader.FromRPC(config.Global().SlaveOptions.RPCKey)
		if err != nil {
			return 0, err
		}
	} else {
		s = loader.FromDir(config.Global().AppPath)
	}

	mainLog.Printf("Detected %v APIs", len(s))

	if config.Global().AuthOverride.ForceAuthProvider {
		for i := range s {
			s[i].AuthProvider = config.Global().AuthOverride.AuthProvider
		}
	}

	if config.Global().AuthOverride.ForceSessionProvider {
		for i := range s {
			s[i].SessionProvider = config.Global().AuthOverride.SessionProvider
		}
	}
	var filter []*APISpec
	for _, v := range s {
		if err := v.Validate(); err != nil {
			mainLog.Infof("Skipping loading spec:%q because it failed validation with error:%v", v.Name, err)
			continue
		}
		filter = append(filter, v)
	}
	apiSpecs = filter
	return len(apiSpecs), nil
}

func syncPolicies() (count int, err error) {
	var pols map[string]user.Policy

	mainLog.Info("Loading policies")

	switch config.Global().Policies.PolicySource {
	case "service":
		if config.Global().Policies.PolicyConnectionString == "" {
			mainLog.Fatal("No connection string or node ID present. Failing.")
		}
		connStr := config.Global().Policies.PolicyConnectionString
		connStr = connStr + "/system/policies"

		mainLog.Info("Using Policies from Dashboard Service")

		pols = LoadPoliciesFromDashboard(connStr, config.Global().NodeSecret, config.Global().Policies.AllowExplicitPolicyID)
	case "rpc":
		mainLog.Debug("Using Policies from RPC")
		pols, err = LoadPoliciesFromRPC(config.Global().SlaveOptions.RPCKey)
	default:
		// this is the only case now where we need a policy record name
		if config.Global().Policies.PolicyRecordName == "" {
			mainLog.Debug("No policy record name defined, skipping...")
			return 0, nil
		}
		pols = LoadPoliciesFromFile(config.Global().Policies.PolicyRecordName)
	}
	mainLog.Infof("Policies found (%d total):", len(pols))
	for id := range pols {
		mainLog.Infof(" - %s", id)
	}

	policiesMu.Lock()
	defer policiesMu.Unlock()
	if len(pols) > 0 {
		policiesByID = pols
	}

	return len(pols), err
}

// stripSlashes removes any trailing slashes from the request's URL
// path.
func stripSlashes(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if trim := strings.TrimRight(path, "/"); trim != path {
			r2 := *r
			r2.URL.Path = trim
			r = &r2
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func controlAPICheckClientCertificate(certLevel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Global().Security.ControlAPIUseMutualTLS {
			if err := CertificateManager.ValidateRequestCertificate(config.Global().Security.Certificates.ControlAPI, r); err != nil {
				doJSONWrite(w, http.StatusForbidden, apiError(err.Error()))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func loadAPIEndpoints(muxer *mux.Router) {
	hostname := config.Global().HostName
	if config.Global().ControlAPIHostname != "" {
		hostname = config.Global().ControlAPIHostname
	}

	if muxer == nil {
		cp := config.Global().ControlAPIPort
		muxer = defaultProxyMux.router(cp, "")
		if muxer == nil {
			if cp != 0 {
				log.Error("Can't find control API router")
			}
			return
		}
	}

	r := mux.NewRouter()
	muxer.PathPrefix("/tyk/").Handler(http.StripPrefix("/tyk",
		stripSlashes(checkIsAPIOwner(controlAPICheckClientCertificate("/gateway/client", InstrumentationMW(r)))),
	))

	if hostname != "" {
		muxer = muxer.Host(hostname).Subrouter()
		mainLog.Info("Control API hostname set: ", hostname)
	}

	if *cli.HTTPProfile || config.Global().HTTPProfile {
		muxer.HandleFunc("/debug/pprof/profile", pprof_http.Profile)
		muxer.HandleFunc("/debug/pprof/{_:.*}", pprof_http.Index)
	}

	r.MethodNotAllowedHandler = MethodNotAllowedHandler{}

	mainLog.Info("Initialising Tyk REST API Endpoints")

	// set up main API handlers
	r.HandleFunc("/reload/group", groupResetHandler).Methods("GET")
	r.HandleFunc("/reload", resetHandler(nil)).Methods("GET")

	if !isRPCMode() {
		r.HandleFunc("/org/keys", orgHandler).Methods("GET")
		r.HandleFunc("/org/keys/{keyName:[^/]*}", orgHandler).Methods("POST", "PUT", "GET", "DELETE")
		r.HandleFunc("/keys/policy/{keyName}", policyUpdateHandler).Methods("POST")
		r.HandleFunc("/keys/create", createKeyHandler).Methods("POST")
		r.HandleFunc("/apis", apiHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/apis/{apiID}", apiHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/health", healthCheckhandler).Methods("GET")
		r.HandleFunc("/oauth/clients/create", createOauthClient).Methods("POST")
		r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", oAuthClientHandler).Methods("PUT")
		r.HandleFunc("/oauth/refresh/{keyName}", invalidateOauthRefresh).Methods("DELETE")
		r.HandleFunc("/cache/{apiID}", invalidateCacheHandler).Methods("DELETE")
	} else {
		mainLog.Info("Node is slaved, REST API minimised")
	}

	r.HandleFunc("/debug", traceHandler).Methods("POST")

	r.HandleFunc("/keys", keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/keys/{keyName:[^/]*}", keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/certs", certHandler).Methods("POST", "GET")
	r.HandleFunc("/certs/{certID:[^/]*}", certHandler).Methods("POST", "GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}", oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName}/tokens", oAuthClientTokensHandler).Methods("GET")

	mainLog.Debug("Loaded API Endpoints")
}

// checkIsAPIOwner will ensure that the accessor of the tyk API has the
// correct security credentials - this is a shared secret between the
// client and the owner and is set in the tyk.conf file. This should
// never be made public!
func checkIsAPIOwner(next http.Handler) http.Handler {
	secret := config.Global().Secret
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get(headers.XTykAuthorization)
		if tykAuthKey != secret {
			// Error
			mainLog.Warning("Attempted administrative access with invalid or missing key!")

			doJSONWrite(w, http.StatusForbidden, apiError("Attempted administrative access with invalid or missing key!"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateOAuthPrefix(apiID string) string {
	return "oauth-data." + apiID + "."
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec *APISpec, muxer *mux.Router) *OAuthManager {
	apiAuthorizePath := spec.Proxy.ListenPath + "tyk/oauth/authorize-client{_:/?}"
	clientAuthPath := spec.Proxy.ListenPath + "oauth/authorize{_:/?}"
	clientAccessPath := spec.Proxy.ListenPath + "oauth/token{_:/?}"

	serverConfig := osin.NewServerConfig()
	serverConfig.ErrorStatusCode = http.StatusForbidden
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes
	serverConfig.RedirectUriSeparator = config.Global().OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := getGlobalStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	osinServer := TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	muxer.Handle(apiAuthorizePath, checkIsAPIOwner(allowMethods(oauthHandlers.HandleGenerateAuthCodeData, "POST")))
	muxer.HandleFunc(clientAuthPath, allowMethods(oauthHandlers.HandleAuthorizePassthrough, "GET", "POST"))
	muxer.HandleFunc(clientAccessPath, addSecureAndCacheHeaders(allowMethods(oauthHandlers.HandleAccessRequest, "GET", "POST")))

	return &oauthManager
}

func addBatchEndpoint(spec *APISpec, muxer *mux.Router) {
	mainLog.Debug("Batch requests enabled for API")
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	batchHandler := BatchRequestHandler{API: spec}
	muxer.HandleFunc(apiBatchPath, batchHandler.HandleBatchRequest)
}

func loadCustomMiddleware(spec *APISpec) ([]string, apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, apidef.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []apidef.MiddlewareDefinition{}
	mwResponseFuncs := []apidef.MiddlewareDefinition{}
	mwDriver := apidef.OttoDriver

	// Set AuthCheck hook
	if spec.CustomMiddleware.AuthCheck.Name != "" {
		mwAuthCheckFunc = spec.CustomMiddleware.AuthCheck
		if spec.CustomMiddleware.AuthCheck.Path != "" {
			// Feed a JS file to Otto
			mwPaths = append(mwPaths, spec.CustomMiddleware.AuthCheck.Path)
		}
	}

	// Load from the configuration
	for _, mwObj := range spec.CustomMiddleware.Pre {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPreFuncs = append(mwPreFuncs, mwObj)
		mainLog.Debug("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range spec.CustomMiddleware.Post {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPostFuncs = append(mwPostFuncs, mwObj)
		mainLog.Debug("Loading custom POST-PROCESSOR middleware: ", mwObj.Name)
	}

	// Load from folders
	for _, folder := range [...]struct {
		name   string
		single *apidef.MiddlewareDefinition
		slice  *[]apidef.MiddlewareDefinition
	}{
		{name: "pre", slice: &mwPreFuncs},
		{name: "auth", single: &mwAuthCheckFunc},
		{name: "post_auth", slice: &mwPostKeyAuthFuncs},
		{name: "post", slice: &mwPostFuncs},
	} {
		globPath := filepath.Join(config.Global().MiddlewarePath, spec.APIID, folder.name, "*.js")
		paths, _ := filepath.Glob(globPath)
		for _, path := range paths {
			mainLog.Debug("Loading file middleware from ", path)

			mwDef := apidef.MiddlewareDefinition{
				Name: strings.Split(filepath.Base(path), ".")[0],
				Path: path,
			}
			mainLog.Debug("-- Middleware name ", mwDef.Name)
			mwDef.RequireSession = strings.HasSuffix(mwDef.Name, "_with_session")
			if mwDef.RequireSession {
				switch folder.name {
				case "post_auth", "post":
					mainLog.Debug("-- Middleware requires session")
				default:
					mainLog.Warning("Middleware requires session, but isn't post-auth: ", mwDef.Name)
				}
			}
			mwPaths = append(mwPaths, path)
			if folder.single != nil {
				*folder.single = mwDef
			} else {
				*folder.slice = append(*folder.slice, mwDef)
			}
		}
	}

	// Set middleware driver, defaults to OttoDriver
	if spec.CustomMiddleware.Driver != "" {
		mwDriver = spec.CustomMiddleware.Driver
	}

	// Load PostAuthCheck hooks
	for _, mwObj := range spec.CustomMiddleware.PostKeyAuth {
		if mwObj.Path != "" {
			// Otto files are specified here
			mwPaths = append(mwPaths, mwObj.Path)
		}
		mwPostKeyAuthFuncs = append(mwPostKeyAuthFuncs, mwObj)
	}

	// Load response hooks
	for _, mw := range spec.CustomMiddleware.Response {
		mwResponseFuncs = append(mwResponseFuncs, mw)
	}

	return mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostKeyAuthFuncs, mwResponseFuncs, mwDriver

}

func createResponseMiddlewareChain(spec *APISpec, responseFuncs []apidef.MiddlewareDefinition) {
	// Create the response processors

	responseChain := make([]TykResponseHandler, len(spec.ResponseProcessors))
	for i, processorDetail := range spec.ResponseProcessors {
		processor := responseProcessorByName(processorDetail.Name)
		if processor == nil {
			mainLog.Error("No such processor: ", processorDetail.Name)
			return
		}
		if err := processor.Init(processorDetail.Options, spec); err != nil {
			mainLog.Debug("Failed to init processor: ", err)
		}
		mainLog.Debug("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = processor
	}

	for _, mw := range responseFuncs {
		processor := responseProcessorByName("custom_mw_res_hook")
		// TODO: perhaps error when plugin support is disabled?
		if processor == nil {
			mainLog.Error("Couldn't find custom middleware processor")
			return
		}
		if err := processor.Init(mw, spec); err != nil {
			mainLog.Debug("Failed to init processor: ", err)
		}
		responseChain = append(responseChain, processor)
	}

	spec.ResponseChain = responseChain
}

func handleCORS(chain *[]alice.Constructor, spec *APISpec) {

	if spec.CORS.Enable {
		mainLog.Debug("CORS ENABLED")
		c := cors.New(cors.Options{
			AllowedOrigins:     spec.CORS.AllowedOrigins,
			AllowedMethods:     spec.CORS.AllowedMethods,
			AllowedHeaders:     spec.CORS.AllowedHeaders,
			ExposedHeaders:     spec.CORS.ExposedHeaders,
			AllowCredentials:   spec.CORS.AllowCredentials,
			MaxAge:             spec.CORS.MaxAge,
			OptionsPassthrough: spec.CORS.OptionsPassthrough,
			Debug:              spec.CORS.Debug,
		})

		*chain = append(*chain, c.Handler)
	}
}

func isRPCMode() bool {
	return config.Global().AuthOverride.ForceAuthProvider &&
		config.Global().AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine
}

func rpcReloadLoop(rpcKey string) {
	for {
		RPCListener.CheckForReload(rpcKey)
	}
}

var reloadMu sync.Mutex

func DoReload() {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	// Initialize/reset the JSVM
	if config.Global().EnableJSVM {
		GlobalEventsJSVM.Init(nil, logrus.NewEntry(log))
	}

	// Load the API Policies
	if _, err := syncPolicies(); err != nil {
		mainLog.Error("Error during syncing policies:", err.Error())
		return
	}

	// load the specs
	if count, err := syncAPISpecs(); err != nil {
		mainLog.Error("Error during syncing apis:", err.Error())
		return
	} else {
		// skip re-loading only if dashboard service reported 0 APIs
		// and current registry had 0 APIs
		if count == 0 && apisByIDLen() == 0 {
			mainLog.Warning("No API Definitions found, not reloading")
			return
		}
	}
	loadGlobalApps()

	mainLog.Info("API reload complete")
}

// startReloadChan and reloadDoneChan are used by the two reload loops
// running in separate goroutines to talk. reloadQueueLoop will use
// startReloadChan to signal to reloadLoop to start a reload, and
// reloadLoop will use reloadDoneChan to signal back that it's done with
// the reload. Buffered simply to not make the goroutines block each
// other.
var startReloadChan = make(chan struct{}, 1)
var reloadDoneChan = make(chan struct{}, 1)

func reloadLoop(tick <-chan time.Time) {
	<-tick
	for range startReloadChan {
		mainLog.Info("reload: initiating")
		DoReload()
		mainLog.Info("reload: complete")

		mainLog.Info("Initiating coprocess reload")
		DoCoprocessReload()

		reloadDoneChan <- struct{}{}
		<-tick
	}
}

// reloadQueue is used by reloadURLStructure to queue a reload. It's not
// buffered, as reloadQueueLoop should pick these up immediately.
var reloadQueue = make(chan func())

func reloadQueueLoop() {
	reloading := false
	var fns []func()
	for {
		select {
		case <-reloadDoneChan:
			for _, fn := range fns {
				fn()
			}
			fns = fns[:0]
			reloading = false
		case fn := <-reloadQueue:
			if fn != nil {
				fns = append(fns, fn)
			}
			if !reloading {
				mainLog.Info("Reload queued")
				startReloadChan <- struct{}{}
				reloading = true
			} else {
				mainLog.Info("Reload already queued")
			}
		}
	}
}

// reloadURLStructure will queue an API reload. The reload will
// eventually create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one. This
// enables a reconfiguration to take place without stopping any requests
// from being handled.
//
// done will be called when the reload is finished. Note that if a
// reload is already queued, another won't be queued, but done will
// still be called when said queued reload is finished.
func reloadURLStructure(done func()) {
	reloadQueue <- done
}

func setupLogger() {
	if config.Global().UseSentry {
		mainLog.Debug("Enabling Sentry support")
		hook, err := logrus_sentry.NewSentryHook(config.Global().SentryCode, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})

		hook.Timeout = 0

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		mainLog.Debug("Sentry hook active")
	}

	if config.Global().UseSyslog {
		mainLog.Debug("Enabling Syslog support")
		hook, err := logrus_syslog.NewSyslogHook(config.Global().SyslogTransport,
			config.Global().SyslogNetworkAddr,
			syslog.LOG_INFO, "")

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		mainLog.Debug("Syslog hook active")
	}

	if config.Global().UseGraylog {
		mainLog.Debug("Enabling Graylog support")
		hook := graylogHook.NewGraylogHook(config.Global().GraylogNetworkAddr,
			map[string]interface{}{"tyk-module": "gateway"})

		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

		mainLog.Debug("Graylog hook active")
	}

	if config.Global().UseLogstash {
		mainLog.Debug("Enabling Logstash support")

		var hook *logstashHook.Hook
		var err error
		var conn net.Conn
		if config.Global().LogstashTransport == "udp" {
			mainLog.Debug("Connecting to Logstash with udp")
			hook, err = logstashHook.NewHook(config.Global().LogstashTransport,
				config.Global().LogstashNetworkAddr,
				appName)
		} else {
			mainLog.Debugf("Connecting to Logstash with %s", config.Global().LogstashTransport)
			conn, err = gas.Dial(config.Global().LogstashTransport, config.Global().LogstashNetworkAddr)
			if err == nil {
				hook, err = logstashHook.NewHookWithConn(conn, appName)
			}
		}

		if err != nil {
			log.Errorf("Error making connection for logstash: %v", err)
		} else {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
			mainLog.Debug("Logstash hook active")
		}
	}

	if config.Global().UseRedisLog {
		hook := newRedisHook()
		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

		mainLog.Debug("Redis log hook active")
	}
}

func initialiseSystem(ctx context.Context) error {
	if isRunningTests() && os.Getenv("TYK_LOGLEVEL") == "" {
		// `go test` without TYK_LOGLEVEL set defaults to no log
		// output
		log.Level = logrus.ErrorLevel
		log.Out = ioutil.Discard
		gorpc.SetErrorLogger(func(string, ...interface{}) {})
		stdlog.SetOutput(ioutil.Discard)
	} else if *cli.DebugMode {
		log.Level = logrus.DebugLevel
		mainLog.Debug("Enabling debug-level output")
	}

	if *cli.Conf != "" {
		mainLog.Debugf("Using %s for configuration", *cli.Conf)
		confPaths = []string{*cli.Conf}
	} else {
		mainLog.Debug("No configuration file defined, will try to use default (tyk.conf)")
	}

	mainLog.Infof("Tyk API Gateway %s", VERSION)

	if !isRunningTests() {
		globalConf := config.Config{}
		if err := config.Load(confPaths, &globalConf); err != nil {
			return err
		}
		if globalConf.PIDFileLocation == "" {
			globalConf.PIDFileLocation = "/var/run/tyk/tyk-gateway.pid"
		}
		// It's necessary to set global conf before and after calling afterConfSetup as global conf
		// is being used by dependencies of the even handler init and then conf is modified again.
		config.SetGlobal(globalConf)
		afterConfSetup(&globalConf)
		config.SetGlobal(globalConf)
	}

	if os.Getenv("TYK_LOGLEVEL") == "" && !*cli.DebugMode {
		level := strings.ToLower(config.Global().LogLevel)
		switch level {
		case "", "info":
			// default, do nothing
		case "error":
			log.Level = logrus.ErrorLevel
		case "warn":
			log.Level = logrus.WarnLevel
		case "debug":
			log.Level = logrus.DebugLevel
		default:
			mainLog.Fatalf("Invalid log level %q specified in config, must be error, warn, debug or info. ", level)
		}
	}

	if config.Global().Storage.Type != "redis" {
		mainLog.Fatal("Redis connection details not set, please ensure that the storage type is set to Redis and that the connection parameters are correct.")
	}

	// suply rpc client globals to join it main loging and instrumentation sub systems
	rpc.Log = log
	rpc.Instrument = instrument

	setupGlobals(ctx)

	globalConf := config.Global()

	if *cli.Port != "" {
		portNum, err := strconv.Atoi(*cli.Port)
		if err != nil {
			mainLog.Error("Port specified in flags must be a number: ", err)
		} else {
			globalConf.ListenPort = portNum
			config.SetGlobal(globalConf)
		}
	}

	// Enable all the loggers
	setupLogger()

	mainLog.Info("PIDFile location set to: ", config.Global().PIDFileLocation)

	pidfile.SetPidfilePath(config.Global().PIDFileLocation)
	if err := pidfile.Write(); err != nil {
		mainLog.Error("Failed to write PIDFile: ", err)
	}

	if globalConf.UseDBAppConfigs && globalConf.Policies.PolicySource != config.DefaultDashPolicySource {
		globalConf.Policies.PolicySource = config.DefaultDashPolicySource
		globalConf.Policies.PolicyConnectionString = globalConf.DBAppConfOptions.ConnectionString
		if globalConf.Policies.PolicyRecordName == "" {
			globalConf.Policies.PolicyRecordName = config.DefaultDashPolicyRecordName
		}
	}

	getHostDetails()
	setupInstrumentation()

	if config.Global().HttpServerOptions.UseLE_SSL {
		go StartPeriodicStateBackup(ctx, &LE_MANAGER)
	}
	return nil
}

// afterConfSetup takes care of non-sensical config values (such as zero
// timeouts) and sets up a few globals that depend on the config.
func afterConfSetup(conf *config.Config) {
	if conf.SlaveOptions.CallTimeout == 0 {
		conf.SlaveOptions.CallTimeout = 30
	}

	if conf.SlaveOptions.PingTimeout == 0 {
		conf.SlaveOptions.PingTimeout = 60
	}

	rpc.GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	rpc.GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	initGenericEventHandlers(conf)
	regexp.ResetCache(time.Second*time.Duration(conf.RegexpCacheExpire), !conf.DisableRegexpCache)

	if conf.HealthCheckEndpointName == "" {
		conf.HealthCheckEndpointName = "hello"
	}
}

var hostDetails struct {
	Hostname string
	PID      int
}

func getHostDetails() {
	var err error
	if hostDetails.PID, err = pidfile.Read(); err != nil {
		mainLog.Error("Failed ot get host pid: ", err)
	}
	if hostDetails.Hostname, err = os.Hostname(); err != nil {
		mainLog.Error("Failed ot get hostname: ", err)
	}
}

func getGlobalStorageHandler(keyPrefix string, hashKeys bool) storage.Handler {
	if config.Global().SlaveOptions.UseRPC {
		return &RPCStorageHandler{
			KeyPrefix: keyPrefix,
			HashKeys:  hashKeys,
		}
	}
	return &storage.RedisCluster{KeyPrefix: keyPrefix, HashKeys: hashKeys}
}

func Start() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli.Init(VERSION, confPaths)
	cli.Parse()
	// Stop gateway process if not running in "start" mode:
	if !cli.DefaultMode {
		os.Exit(0)
	}

	SetNodeID("solo-" + uuid.NewV4().String())

	if err := initialiseSystem(ctx); err != nil {
		mainLog.Fatalf("Error initialising system: %v", err)
	}

	if config.Global().ControlAPIPort == 0 {
		mainLog.Warn("The control_api_port should be changed for production")
	}
	setupPortsWhitelist()

	onFork := func() {
		mainLog.Warning("PREPARING TO FORK")

		// if controlListener != nil {
		// 	if err := controlListener.Close(); err != nil {
		// 		mainLog.Error("Control listen handler exit: ", err)
		// 	}
		// 	mainLog.Info("Control listen closed")
		// }

		if config.Global().UseDBAppConfigs {
			mainLog.Info("Stopping heartbeat")
			DashService.StopBeating()
			mainLog.Info("Waiting to de-register")
			time.Sleep(10 * time.Second)

			os.Setenv("TYK_SERVICE_NONCE", ServiceNonce)
			os.Setenv("TYK_SERVICE_NODEID", GetNodeID())
		}
	}
	err := again.ListenFrom(&defaultProxyMux.again, onFork)
	if err != nil {
		mainLog.Errorf("Initializing again %s", err)
	}
	checkup.Run(config.Global())
	if tr := config.Global().Tracer; tr.Enabled {
		trace.SetupTracing(tr.Name, tr.Options)
		trace.SetLogger(mainLog)
		defer trace.Close()
	}
	start()

	// Wait while Redis connection pools are ready before start serving traffic
	if !storage.IsConnected() {
		mainLog.Fatal("Redis connection pools are not ready. Exiting...")
	}
	mainLog.Info("Redis connection pools are ready")

	if *cli.MemProfile {
		mainLog.Debug("Memory profiling active")
		var err error
		if memProfFile, err = os.Create("tyk.mprof"); err != nil {
			panic(err)
		}
		defer memProfFile.Close()
	}
	if *cli.CPUProfile {
		mainLog.Info("Cpu profiling active")
		cpuProfFile, err := os.Create("tyk.prof")
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(cpuProfFile)
		defer pprof.StopCPUProfile()
	}
	if *cli.BlockProfile {
		mainLog.Info("Block profiling active")
		runtime.SetBlockProfileRate(1)
	}
	if *cli.MutexProfile {
		mainLog.Info("Mutex profiling active")
		runtime.SetMutexProfileFraction(1)
	}

	// TODO: replace goagain with something that support multiple listeners
	// Example: https://gravitational.com/blog/golang-ssh-bastion-graceful-restarts/
	startServer()

	if again.Child() {
		// This is a child process, we need to murder the parent now
		if err := again.Kill(); err != nil {
			mainLog.Fatal(err)
		}
	}
	again.Wait(&defaultProxyMux.again)
	mainLog.Info("Stop signal received.")
	if err := defaultProxyMux.again.Close(); err != nil {
		mainLog.Error("Closing listeners: ", err)
	}
	// stop analytics workers
	if config.Global().EnableAnalytics && analytics.Store == nil {
		analytics.Stop()
	}

	// if using async session writes stop workers
	if config.Global().UseAsyncSessionWrite {
		DefaultOrgStore.Stop()
		for i := range apiSpecs {
			apiSpecs[i].StopSessionManagerPool()
		}

	}

	// write pprof profiles
	writeProfiles()

	if config.Global().UseDBAppConfigs {
		mainLog.Info("Stopping heartbeat...")
		DashService.StopBeating()
		time.Sleep(2 * time.Second)
		DashService.DeRegister()
	}

	mainLog.Info("Terminating.")

	time.Sleep(time.Second)
}

func writeProfiles() {
	if *cli.BlockProfile {
		f, err := os.Create("tyk.blockprof")
		if err != nil {
			panic(err)
		}
		if err = pprof.Lookup("block").WriteTo(f, 0); err != nil {
			panic(err)
		}
		f.Close()
	}
	if *cli.MutexProfile {
		f, err := os.Create("tyk.mutexprof")
		if err != nil {
			panic(err)
		}
		if err = pprof.Lookup("mutex").WriteTo(f, 0); err != nil {
			panic(err)
		}
		f.Close()
	}
}

func start() {
	// Set up a default org manager so we can traverse non-live paths
	if !config.Global().SupressDefaultOrgStore {
		mainLog.Debug("Initialising default org store")
		DefaultOrgStore.Init(getGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(getGlobalStorageHandler(CloudHandler, "orgkey.", false))
		DefaultQuotaStore.Init(getGlobalStorageHandler("orgkey.", false))
	}

	// Start listening for reload messages
	if !config.Global().SuppressRedisSignalReload {
		go startPubSubLoop()
	}

	if slaveOptions := config.Global().SlaveOptions; slaveOptions.UseRPC {
		mainLog.Debug("Starting RPC reload listener")
		RPCListener = RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			SuppressRegister: true,
		}

		RPCListener.Connect()
		go rpcReloadLoop(slaveOptions.RPCKey)
		go RPCListener.StartRPCKeepaliveWatcher()
		go RPCListener.StartRPCLoopCheck(slaveOptions.RPCKey)
	}

	// 1s is the minimum amount of time between hot reloads. The
	// interval counts from the start of one reload to the next.
	go reloadLoop(time.Tick(time.Second))
	go reloadQueueLoop()
}

func dashboardServiceInit() {
	if DashService == nil {
		DashService = &HTTPDashboardHandler{}
		DashService.Init()
	}
}

func handleDashboardRegistration() {
	if !config.Global().UseDBAppConfigs {
		return
	}

	dashboardServiceInit()

	// connStr := buildConnStr("/register/node")
	if err := DashService.Register(); err != nil {
		dashLog.Fatal("Registration failed: ", err)
	}

	go DashService.StartBeating()
}

var drlOnce sync.Once

func startDRL() {
	switch {
	case config.Global().ManagementNode:
		return
	case config.Global().EnableSentinelRateLimiter, config.Global().EnableRedisRollingLimiter:
		return
	}
	mainLog.Info("Initialising distributed rate limiter")
	setupDRL()
	startRateLimitNotifications()
}

func setupPortsWhitelist() {
	// setup listen and control ports as whitelisted
	globalConf := config.Global()
	w := globalConf.PortWhiteList
	if w == nil {
		w = make(map[string]config.PortWhiteList)
	}
	protocol := "http"
	if globalConf.HttpServerOptions.UseSSL {
		protocol = "https"
	}
	ls := config.PortWhiteList{}
	if v, ok := w[protocol]; ok {
		ls = v
	}
	ls.Ports = append(ls.Ports, globalConf.ListenPort)
	if globalConf.ControlAPIPort != 0 {
		ls.Ports = append(ls.Ports, globalConf.ControlAPIPort)
	}
	w[protocol] = ls
	globalConf.PortWhiteList = w
	config.SetGlobal(globalConf)
}

func startServer() {
	// Ensure that Control listener and default http listener running on first start
	muxer := &proxyMux{}

	router := mux.NewRouter()
	loadAPIEndpoints(router)
	muxer.setRouter(config.Global().ControlAPIPort, "", router)

	if muxer.router(config.Global().ListenPort, "") == nil {
		muxer.setRouter(config.Global().ListenPort, "", mux.NewRouter())
	}

	defaultProxyMux.swap(muxer)

	// handle dashboard registration and nonces if available
	handleDashboardRegistration()

	// at this point NodeID is ready to use by DRL
	drlOnce.Do(startDRL)

	mainLog.Infof("Tyk Gateway started (%s)", VERSION)
	address := config.Global().ListenAddress
	if config.Global().ListenAddress == "" {
		address = "(open interface)"
	}
	mainLog.Info("--> Listening on address: ", address)
	mainLog.Info("--> Listening on port: ", config.Global().ListenPort)
	mainLog.Info("--> PID: ", hostDetails.PID)
	if !rpc.IsEmergencyMode() {
		DoReload()
	}
}
