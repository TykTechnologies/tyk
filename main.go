package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"log/syslog"
	"net"
	"net/http"
	pprof_http "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/docopt/docopt.go"
	"github.com/evalphobia/logrus_sentry"
	"github.com/facebookgo/pidfile"
	"github.com/gemnasium/logrus-graylog-hook"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/lonelycode/gorpc"
	"github.com/lonelycode/osin"
	"github.com/rs/cors"
	uuid "github.com/satori/go.uuid"
	"rsc.io/letsencrypt"

	"github.com/TykTechnologies/goagain"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
)

var (
	log                      = logger.Get()
	globalConf               config.Config
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

	apisMu   sync.RWMutex
	apisByID = map[string]*APISpec{}

	keyGen DefaultKeyGenerator

	policiesMu   sync.RWMutex
	policiesByID = map[string]Policy{}

	mainRouter    *mux.Router
	defaultRouter *mux.Router
	controlRouter *mux.Router
	LE_MANAGER    letsencrypt.Manager
	LE_FIRSTRUN   bool

	NodeID string

	runningTests = false

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
)

func getApiSpec(apiID string) *APISpec {
	apisMu.RLock()
	spec := apisByID[apiID]
	apisMu.RUnlock()
	return spec
}

// Display configuration options
func displayConfig() {
	address := globalConf.ListenAddress
	if globalConf.ListenAddress == "" {
		address = "(open interface)"
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on address: ", address)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on port: ", globalConf.ListenPort)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> PID: ", HostDetails.PID)
}

func pingTest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Tiki")
}

// Create all globals and init connection handlers
func setupGlobals() {
	mainRouter = mux.NewRouter()
	defaultRouter = mainRouter

	controlRouter = mux.NewRouter()

	if globalConf.EnableAnalytics && globalConf.Storage.Type != "redis" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Panic("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	// Initialise our Host Checker
	healthCheckStore := &RedisClusterStorageManager{KeyPrefix: "host-checker:"}
	InitHostCheckManager(healthCheckStore)

	if globalConf.EnableAnalytics && analytics.Store == nil {
		globalConf.LoadIgnoredIPs()
		analyticsStore := RedisClusterStorageManager{KeyPrefix: "analytics-"}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Setting up analytics DB connection")

		analytics.Store = &analyticsStore
		analytics.Init()

		if globalConf.AnalyticsConfig.Type == "rpc" {
			log.Debug("Using RPC cache purge")

			purger := RPCPurger{Store: &analyticsStore}
			purger.Connect()
			analytics.Clean = &purger
			go analytics.Clean.PurgeLoop(10 * time.Second)
		}

	}

	// Load all the files that have the "error" prefix.
	templatesDir := filepath.Join(globalConf.TemplatePath, "error*")
	templates = template.Must(template.ParseGlob(templatesDir))

	// Set up global JSVM
	if globalConf.EnableJSVM {
		GlobalEventsJSVM.Init()
	}

	if globalConf.CoProcessOptions.EnableCoProcess {
		CoProcessInit()
	}

	// Get the notifier ready
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Notifier will not work in hybrid mode")
	mainNotifierStore := RedisClusterStorageManager{}
	mainNotifierStore.Connect()
	MainNotifier = RedisNotifier{&mainNotifierStore, RedisPubSubChannel}

	if globalConf.Monitor.EnableTriggerMonitors {
		h := &WebHookHandler{}
		if err := h.Init(globalConf.Monitor.Config); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to initialise monitor! ", err)
		} else {
			MonitoringHandler = h
		}
	}

	if globalConf.AnalyticsConfig.NormaliseUrls.Enabled {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Setting up analytics normaliser")
		globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()
	}

}

func buildConnStr(resource string) string {

	if globalConf.DBAppConfOptions.ConnectionString == "" && globalConf.DisableDashboardZeroConf {
		log.Fatal("Connection string is empty, failing.")
		return ""
	}

	if !globalConf.DisableDashboardZeroConf && globalConf.DBAppConfOptions.ConnectionString == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Waiting for zeroconf signal...")
		for globalConf.DBAppConfOptions.ConnectionString == "" {
			time.Sleep(1 * time.Second)
		}
	}

	connStr := globalConf.DBAppConfOptions.ConnectionString
	connStr = connStr + resource
	return connStr
}

// Pull API Specs from configuration
var APILoader = APIDefinitionLoader{}

func getAPISpecs() []*APISpec {
	var apiSpecs []*APISpec

	if globalConf.UseDBAppConfigs {

		connStr := buildConnStr("/system/apis")
		apiSpecs = APILoader.LoadDefinitionsFromDashboardService(connStr, globalConf.NodeSecret)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Downloading API Configurations from Dashboard Service")
	} else if globalConf.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using RPC Configuration")

		apiSpecs = APILoader.LoadDefinitionsFromRPC(globalConf.SlaveOptions.RPCKey)
	} else {
		apiSpecs = APILoader.LoadDefinitions(globalConf.AppPath)
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Printf("Detected %v APIs", len(apiSpecs))

	if globalConf.AuthOverride.ForceAuthProvider {
		for i := range apiSpecs {
			apiSpecs[i].AuthProvider = globalConf.AuthOverride.AuthProvider
		}
	}

	if globalConf.AuthOverride.ForceSessionProvider {
		for i := range apiSpecs {
			apiSpecs[i].SessionProvider = globalConf.AuthOverride.SessionProvider
		}
	}

	return apiSpecs
}

func getPolicies() {
	pols := make(map[string]Policy)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading policies")

	switch globalConf.Policies.PolicySource {
	case "service":
		if globalConf.Policies.PolicyConnectionString != "" {
			connStr := globalConf.Policies.PolicyConnectionString
			connStr = connStr + "/system/policies"

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Using Policies from Dashboard Service")

			pols = LoadPoliciesFromDashboard(connStr, globalConf.NodeSecret, globalConf.Policies.AllowExplicitPolicyID)

		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatal("No connection string or node ID present. Failing.")
		}

	case "rpc":
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using Policies from RPC")
		pols = LoadPoliciesFromRPC(globalConf.SlaveOptions.RPCKey)
	default:
		// this is the only case now where we need a policy record name
		if globalConf.Policies.PolicyRecordName == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("No policy record name defined, skipping...")
			return
		}
		pols = LoadPoliciesFromFile(globalConf.Policies.PolicyRecordName)
	}

	if len(pols) > 0 {
		policiesMu.Lock()
		policiesByID = pols
		policiesMu.Unlock()
	}
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(muxer *mux.Router) {
	hostname := globalConf.HostName
	if globalConf.ControlAPIHostname != "" {
		hostname = globalConf.ControlAPIHostname
	}
	r := mux.NewRouter()
	muxer.PathPrefix("/tyk").Handler(http.StripPrefix("/tyk",
		checkIsAPIOwner(InstrumentationMW(r)),
	))
	if hostname != "" {
		r = r.Host(hostname).Subrouter()
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Control API hostname set: ", hostname)
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialising Tyk REST API Endpoints")

	// set up main API handlers
	r.HandleFunc("/reload/group{_:/?}", allowMethods(groupResetHandler, "GET"))
	r.HandleFunc("/reload{_:/?}", allowMethods(resetHandler(nil), "GET"))

	if !isRPCMode() {
		r.HandleFunc("/org/keys/{keyName:[^/]*}", allowMethods(orgHandler, "POST", "PUT", "GET", "DELETE"))
		r.HandleFunc("/keys/policy/{keyName}", allowMethods(policyUpdateHandler, "POST"))
		r.HandleFunc("/keys/create{_:/?}", allowMethods(createKeyHandler, "POST"))
		r.HandleFunc("/apis{_:/?}", allowMethods(apiHandler, "GET", "POST", "PUT", "DELETE"))
		r.HandleFunc("/apis/{apiID}", allowMethods(apiHandler, "GET", "POST", "PUT", "DELETE"))
		r.HandleFunc("/health{_:/?}", allowMethods(healthCheckhandler, "GET"))
		r.HandleFunc("/oauth/clients/create{_:/?}", allowMethods(createOauthClient, "POST"))
		r.HandleFunc("/oauth/refresh/{keyName}", allowMethods(invalidateOauthRefresh, "DELETE"))
		r.HandleFunc("/cache/{apiID}{_:/?}", allowMethods(invalidateCacheHandler, "DELETE"))
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Node is slaved, REST API minimised")
	}

	r.HandleFunc("/keys/{keyName:[^/]*}", allowMethods(keyHandler, "POST", "PUT", "GET", "DELETE"))
	r.HandleFunc("/oauth/clients/{apiID}", allowMethods(oAuthClientHandler, "GET", "DELETE"))
	r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", allowMethods(oAuthClientHandler, "GET", "DELETE"))

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Loaded API Endpoints")
}

// checkIsAPIOwner will ensure that the accessor of the tyk API has the
// correct security credentials - this is a shared secret between the
// client and the owner and is set in the tyk.conf file. This should
// never be made public!
func checkIsAPIOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get("X-Tyk-Authorization")
		if tykAuthKey != globalConf.Secret {
			// Error
			log.Warning("Attempted administrative access with invalid or missing key!")

			doJSONWrite(w, 403, apiError("Forbidden"))
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
	serverConfig.ErrorStatusCode = 403
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes
	serverConfig.RedirectUriSeparator = globalConf.OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := getGlobalStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	osinServer := TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	muxer.Handle(apiAuthorizePath, checkIsAPIOwner(http.HandlerFunc(allowMethods(oauthHandlers.HandleGenerateAuthCodeData, "POST"))))
	muxer.HandleFunc(clientAuthPath, allowMethods(oauthHandlers.HandleAuthorizePassthrough, "GET", "POST"))
	muxer.HandleFunc(clientAccessPath, allowMethods(oauthHandlers.HandleAccessRequest, "GET", "POST"))

	return &oauthManager
}

func addBatchEndpoint(spec *APISpec, muxer *mux.Router) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Batch requests enabled for API")
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	batchHandler := BatchRequestHandler{API: spec}
	muxer.HandleFunc(apiBatchPath, batchHandler.HandleBatchRequest)
}

func loadCustomMiddleware(referenceSpec *APISpec) ([]string, apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, apidef.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []apidef.MiddlewareDefinition{}
	mwDriver := apidef.OttoDriver

	// Set AuthCheck hook
	if referenceSpec.CustomMiddleware.AuthCheck.Name != "" {
		mwAuthCheckFunc = referenceSpec.CustomMiddleware.AuthCheck
		if referenceSpec.CustomMiddleware.AuthCheck.Path != "" {
			// Feed a JS file to Otto
			mwPaths = append(mwPaths, referenceSpec.CustomMiddleware.AuthCheck.Path)
		}
	}

	// Load from the configuration
	for _, mwObj := range referenceSpec.CustomMiddleware.Pre {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPreFuncs = append(mwPreFuncs, mwObj)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range referenceSpec.CustomMiddleware.Post {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPostFuncs = append(mwPostFuncs, mwObj)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading custom POST-PROCESSOR middleware: ", mwObj.Name)
	}

	// Load from folders
	for _, folder := range [...]struct {
		name    string
		single  *apidef.MiddlewareDefinition
		slice   *[]apidef.MiddlewareDefinition
		session bool
	}{
		{name: "pre", slice: &mwPreFuncs, session: true},
		{name: "auth", single: &mwAuthCheckFunc},
		{name: "post_auth", slice: &mwPostKeyAuthFuncs, session: true},
		{name: "post", slice: &mwPostFuncs, session: true},
	} {
		dirPath := filepath.Join(globalConf.MiddlewarePath, referenceSpec.APIID, folder.name)
		files, _ := ioutil.ReadDir(dirPath)
		for _, f := range files {
			if strings.Contains(f.Name(), ".js") {
				filePath := filepath.Join(dirPath, f.Name())
				log.WithFields(logrus.Fields{
					"prefix": "main",
				}).Debug("Loading file middleware from ", filePath)
				mwObjName := strings.Split(f.Name(), ".")[0]
				log.WithFields(logrus.Fields{
					"prefix": "main",
				}).Debug("-- Middleware name ", mwObjName)

				mwDef := apidef.MiddlewareDefinition{}
				mwDef.Name = mwObjName
				mwDef.Path = filePath
				if folder.session {
					mwDef.RequireSession = strings.Contains(mwObjName, "_with_session")
					log.WithFields(logrus.Fields{
						"prefix": "main",
					}).Debug("-- Middleware requires session: ", mwDef.RequireSession)
				}
				mwPaths = append(mwPaths, filePath)
				if folder.single != nil {
					*folder.single = mwDef
				} else {
					*folder.slice = append(*folder.slice, mwDef)
				}
			}
		}
	}

	// Set middleware driver, defaults to OttoDriver
	if referenceSpec.CustomMiddleware.Driver != "" {
		mwDriver = referenceSpec.CustomMiddleware.Driver
	}

	// Load PostAuthCheck hooks
	for _, mwObj := range referenceSpec.CustomMiddleware.PostKeyAuth {
		if mwObj.Path != "" {
			// Otto files are specified here
			mwPaths = append(mwPaths, mwObj.Path)
		}
		mwPostKeyAuthFuncs = append(mwPostKeyAuthFuncs, mwObj)
	}

	return mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostKeyAuthFuncs, mwDriver
}

func creeateResponseMiddlewareChain(referenceSpec *APISpec) {
	// Create the response processors

	responseChain := make([]TykResponseHandler, len(referenceSpec.ResponseProcessors))
	for i, processorDetail := range referenceSpec.ResponseProcessors {
		processor, err := GetResponseProcessorByName(processorDetail.Name)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to load processor! ", err)
			return
		}
		_ = processor.Init(processorDetail.Options, referenceSpec)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = processor
	}
	referenceSpec.ResponseChain = responseChain
	if len(responseChain) > 0 {
		referenceSpec.ResponseHandlersActive = true
	}
}

func handleCORS(chain *[]alice.Constructor, spec *APISpec) {

	if spec.CORS.Enable {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("CORS ENABLED")
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
	return globalConf.AuthOverride.ForceAuthProvider &&
		globalConf.AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine
}

type SortableAPISpecListByListen []*APISpec

func (s SortableAPISpecListByListen) Len() int {
	return len(s)
}
func (s SortableAPISpecListByListen) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortableAPISpecListByListen) Less(i, j int) bool {
	return len(s[i].Proxy.ListenPath) > len(s[j].Proxy.ListenPath)
}

type SortableAPISpecListByHost []*APISpec

func (s SortableAPISpecListByHost) Len() int {
	return len(s)
}
func (s SortableAPISpecListByHost) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortableAPISpecListByHost) Less(i, j int) bool {
	return len(s[i].Domain) > len(s[j].Domain)
}

func notifyAPILoaded(spec *APISpec) {
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

}

func rpcReloadLoop(rpcKey string) {
	for {
		RPCListener.CheckForReload(rpcKey)
	}
}

func doReload() {
	// Load the API Policies
	getPolicies()

	// load the specs
	specs := getAPISpecs()
	if len(specs) == 0 {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("No API Definitions found, not reloading")
		return
	}

	// We have updated specs, lets load those...

	// Reset the JSVM
	if globalConf.EnableJSVM {
		GlobalEventsJSVM.Init()
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Preparing new router")
	newRouter := mux.NewRouter()
	mainRouter = newRouter

	if globalConf.ControlAPIPort == 0 {
		loadAPIEndpoints(newRouter)
	}
	loadApps(specs, newRouter)

	newServeMux := http.NewServeMux()
	newServeMux.Handle("/", mainRouter)

	http.DefaultServeMux = newServeMux

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("API reload complete")

	// Unset these
	RPC_EmergencyModeLoaded = false
	RPC_EmergencyMode = false
}

// reloadChan is a queue for incoming reload requests. At most, we want
// to have one reload running and one queued. If one is already queued,
// any reload requests should do nothing as a reload is already going to
// start at some point. Hence, buffer of size 1.
// If the queued func is non-nil, it is called once the reload is done.
var reloadChan = make(chan func(), 1)

func reloadLoop(tick <-chan time.Time) {
	<-tick
	for fn := range reloadChan {
		log.Info("Initiating reload")
		doReload()
		log.Info("Initiating coprocess reload")
		doCoprocessReload()

		if fn != nil {
			fn()
		}
		<-tick
	}
}

// reloadURLStructure will create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one, this enables a
// reconfiguration to take place without stopping any requests from being handled.
// It returns true if it was queued, or false if it wasn't.
func reloadURLStructure(fn func()) bool {
	select {
	case reloadChan <- fn:
		log.Info("Reload queued")
		return true
	default:
		log.Info("Reload already queued")
		return false
	}
}

func setupLogger() {
	if globalConf.UseSentry {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Sentry support")
		hook, err := logrus_sentry.NewSentryHook(globalConf.SentryCode, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})

		hook.Timeout = 0

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Sentry hook active")
	}

	if globalConf.UseSyslog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Syslog support")
		hook, err := logrus_syslog.NewSyslogHook(globalConf.SyslogTransport,
			globalConf.SyslogNetworkAddr,
			syslog.LOG_INFO, "")

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Syslog hook active")
	}

	if globalConf.UseGraylog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Graylog support")
		hook := graylog.NewGraylogHook(globalConf.GraylogNetworkAddr,
			map[string]interface{}{"tyk-module": "gateway"})

		log.Hooks.Add(hook)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Graylog hook active")
	}

	if globalConf.UseLogstash {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Logstash support")
		hook, err := logrus_logstash.NewHook(globalConf.LogstashTransport,
			globalConf.LogstashNetworkAddr,
			"tyk-gateway")

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Logstash hook active")
	}

	if globalConf.UseRedisLog {
		redisHook := newRedisHook()
		log.Hooks.Add(redisHook)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Redis log hook active")
	}

}

func initialiseSystem(arguments map[string]interface{}) error {

	// Enable command mode
	for _, opt := range commandModeOptions {
		v := arguments[opt]
		if v != nil && v != false {
			handleCommandModeArgs(arguments)
			os.Exit(0)
		}
	}

	if runningTests && os.Getenv("TYK_LOGLEVEL") == "" {
		// `go test` without TYK_LOGLEVEL set defaults to no log
		// output
		log.Level = logrus.ErrorLevel
		log.Out = ioutil.Discard
		gorpc.SetErrorLogger(func(string, ...interface{}) {})
	} else if arguments["--debug"] == true {
		log.Level = logrus.DebugLevel
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling debug-level output")
	}

	if conf := arguments["--conf"]; conf != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debugf("Using %s for configuration", conf.(string))
		confPaths = []string{conf.(string)}
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("No configuration file defined, will try to use default (tyk.conf)")
	}

	if !runningTests {
		if err := config.Load(confPaths, &globalConf); err != nil {
			return err
		}
		afterConfSetup(&globalConf)
	}

	if globalConf.Storage.Type != "redis" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatal("Redis connection details not set, please ensure that the storage type is set to Redis and that the connection parameters are correct.")
	}

	setupGlobals()

	if port := arguments["--port"]; port != nil {
		portNum, err := strconv.Atoi(port.(string))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Port specified in flags must be a number: ", err)
		} else {
			globalConf.ListenPort = portNum
		}
	}

	// Enable all the loggers
	setupLogger()

	if globalConf.PIDFileLocation == "" {
		globalConf.PIDFileLocation = "/var/run/tyk-gateway.pid"
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("PIDFile location set to: ", globalConf.PIDFileLocation)

	pidfile.SetPidfilePath(globalConf.PIDFileLocation)
	if err := pidfile.Write(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Failed to write PIDFile: ", err)
	}

	getHostDetails()

	//doInstrumentation, _ := arguments["--log-instrumentation"].(bool)
	//SetupInstrumentation(doInstrumentation)
	SetupInstrumentation(true)

	go StartPeriodicStateBackup(&LE_MANAGER)

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
	GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	conf.EventTriggers = InitGenericEventHandlers(conf.EventHandlers)
}

type AuditHostDetails struct {
	Hostname string
	PID      int
}

var HostDetails AuditHostDetails

func getHostDetails() {
	var err error
	if HostDetails.PID, err = pidfile.Read(); err != nil {
		log.Error("Failed ot get host pid: ", err)
	}

	if HostDetails.Hostname, err = os.Hostname(); err != nil {
		log.Error("Failed ot get hostname: ", err)
	}
}

func getCmdArguments() map[string]interface{} {
	usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help                    Show this screen
		--conf=FILE                  Load a named configuration file
		--port=PORT                  Listen on PORT (overrides confg file)
		--memprofile                 Generate a memory profile
		--cpuprofile                 Generate a cpu profile
		--httpprofile                Expose runtime profiling data via HTTP
		--debug                      Enable Debug output
		--import-blueprint=<file>    Import an API Blueprint file
		--import-swagger=<file>      Import a Swagger file
		--create-api                 Creates a new API Definition from the blueprint
		--org-id=<id>                Assign the API Defintition to this org_id (required with create)
		--upstream-target=<url>      Set the upstream target for the definition
		--as-mock                    Creates the API as a mock based on example fields
		--for-api=<path>             Adds blueprint to existing API Defintition as version
		--as-version=<version>       The version number to use when inserting
		--log-instrumentation        Output instrumentation data to stdout
	`
	arguments, err := docopt.Parse(usage, nil, true, VERSION, false)
	if err != nil {
		// docopt will exit on its own if there are any user
		// errors, such as an unknown flag being used.
		panic(err)
	}
	return arguments
}

var KeepaliveRunning bool

func startRPCKeepaliveWatcher(engine *RPCStorageHandler) {
	if KeepaliveRunning {
		return
	}

	go func() {
		log.WithFields(logrus.Fields{
			"prefix": "RPC Conn Mgr",
		}).Info("[RPC Conn Mgr] Starting keepalive watcher...")
		for {
			KeepaliveRunning = true
			rpcKeepAliveCheck(engine)
			if engine == nil {
				log.WithFields(logrus.Fields{
					"prefix": "RPC Conn Mgr",
				}).Info("No engine, break")
				KeepaliveRunning = false
				break
			}
			if engine.Killed {
				log.WithFields(logrus.Fields{
					"prefix": "RPC Conn Mgr",
				}).Debug("[RPC Conn Mgr] this connection killed")
				KeepaliveRunning = false
				break
			}
		}
	}()
}

func getGlobalLocalStorageHandler(keyPrefix string, hashKeys bool) StorageHandler {
	return &RedisClusterStorageManager{KeyPrefix: keyPrefix, HashKeys: hashKeys}
}

func getGlobalLocalCacheStorageHandler(keyPrefix string, hashKeys bool) StorageHandler {
	return &RedisClusterStorageManager{KeyPrefix: keyPrefix, HashKeys: hashKeys, IsCache: true}
}

func getGlobalStorageHandler(keyPrefix string, hashKeys bool) StorageHandler {
	if globalConf.SlaveOptions.UseRPC {
		return &RPCStorageHandler{KeyPrefix: keyPrefix, HashKeys: hashKeys, UserKey: globalConf.SlaveOptions.APIKey, Address: globalConf.SlaveOptions.ConnectionString}
	}
	return &RedisClusterStorageManager{KeyPrefix: keyPrefix, HashKeys: hashKeys}
}

// Handles pre-fork actions if we get a SIGHUP2
var amForked bool

func onFork() {
	if globalConf.UseDBAppConfigs {
		log.Info("Stopping heartbeat")
		DashService.StopBeating()

		log.Info("Waiting to de-register")
		time.Sleep(10 * time.Second)

		os.Setenv("TYK_SERVICE_NONCE", ServiceNonce)
		os.Setenv("TYK_SERVICE_NODEID", NodeID)
	}

	amForked = true
}

func generateRandomNodeID() string {
	u := uuid.NewV4()
	return "solo-" + u.String()
}

func main() {
	arguments := getCmdArguments()
	NodeID = generateRandomNodeID()
	l, goAgainErr := goagain.Listener(onFork)
	controlListener, goAgainErr := goagain.Listener(onFork)

	if err := initialiseSystem(arguments); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatalf("Error initialising system: %v", err)
	}
	start(arguments)

	if goAgainErr != nil {
		var err error
		if l, err = generateListener(0); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatalf("Error starting listener: %s", err)
		}

		if globalConf.ControlAPIPort > 0 {
			if controlListener, err = generateListener(globalConf.ControlAPIPort); err != nil {
				log.WithFields(logrus.Fields{
					"prefix": "main",
				}).Fatalf("Error starting control API listener: %s", err)
			}
		}

		listen(l, controlListener, goAgainErr)
	} else {
		listen(l, controlListener, goAgainErr)

		// Kill the parent, now that the child has started successfully.
		log.Debug("KILLING PARENT PROCESS")
		if err := goagain.Kill(); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatalln(err)
		}
	}

	// Block the main goroutine awaiting signals.
	if _, err := goagain.Wait(l); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatalln(err)
	}

	// Do whatever's necessary to ensure a graceful exit
	// In this case, we'll simply stop listening and wait one second.
	if err := l.Close(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Listen handler exit: ", err)
	}

	if !amForked {
		log.Info("Stop signal received.")

		if globalConf.UseDBAppConfigs {
			log.Info("Stopping heartbeat...")
			DashService.StopBeating()
			time.Sleep(2 * time.Second)
			DashService.DeRegister()
		}

		log.Info("Terminating.")
	} else {
		log.Info("Terminated from fork.")
	}

	time.Sleep(3 * time.Second)
}

func start(arguments map[string]interface{}) {
	if arguments["--memprofile"] == true {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Memory profiling active")
		var err error
		if memProfFile, err = os.Create("tyk.mprof"); err != nil {
			panic(err)
		}
		defer memProfFile.Close()
	}
	if arguments["--cpuprofile"] == true {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Cpu profiling active")
		cpuProfFile, err := os.Create("tyk.prof")
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(cpuProfFile)
		defer pprof.StopCPUProfile()
	}
	if arguments["--httpprofile"] == true {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Adding pprof endpoints")

		defaultRouter.HandleFunc("/debug/pprof/{_:.*}", pprof_http.Index)
	}

	// Set up a default org manager so we can traverse non-live paths
	if !globalConf.SupressDefaultOrgStore {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Initialising default org store")
		//DefaultOrgStore.Init(&RedisClusterStorageManager{KeyPrefix: "orgkey."})
		DefaultOrgStore.Init(getGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(getGlobalStorageHandler(CloudHandler, "orgkey.", false))
		DefaultQuotaStore.Init(getGlobalStorageHandler("orgkey.", false))
	}

	if globalConf.ControlAPIPort == 0 {
		loadAPIEndpoints(defaultRouter)
	}

	// Start listening for reload messages
	if !globalConf.SuppressRedisSignalReload {
		go startPubSubLoop()
	}

	if globalConf.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Starting RPC reload listener")
		RPCListener = RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			UserKey:          globalConf.SlaveOptions.APIKey,
			Address:          globalConf.SlaveOptions.ConnectionString,
			SuppressRegister: true,
		}
		RPCListener.Connect()
		go rpcReloadLoop(globalConf.SlaveOptions.RPCKey)
		go RPCListener.StartRPCLoopCheck(globalConf.SlaveOptions.RPCKey)
	}

	// 1s is the minimum amount of time between hot reloads. The
	// interval counts from the start of one reload to the next.
	go reloadLoop(time.Tick(time.Second))
}

func generateListener(listenPort int) (net.Listener, error) {
	listenAddress := globalConf.ListenAddress
	if listenPort == 0 {
		listenPort = globalConf.ListenPort
	}

	targetPort := fmt.Sprintf("%s:%d", listenAddress, listenPort)

	if globalConf.HttpServerOptions.UseSSL {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("--> Using SSL (https)")
		certs := make([]tls.Certificate, len(globalConf.HttpServerOptions.Certificates))
		certNameMap := make(map[string]*tls.Certificate)
		for i, certData := range globalConf.HttpServerOptions.Certificates {
			cert, err := tls.LoadX509KeyPair(certData.CertFile, certData.KeyFile)
			if err != nil {
				log.WithFields(logrus.Fields{
					"prefix": "main",
				}).Fatalf("Server error: loadkeys: %s", err)
			}
			certs[i] = cert
			certNameMap[certData.Name] = &certs[i]
		}

		config := tls.Config{
			Certificates:       certs,
			NameToCertificate:  certNameMap,
			ServerName:         globalConf.HttpServerOptions.ServerName,
			MinVersion:         globalConf.HttpServerOptions.MinVersion,
			InsecureSkipVerify: globalConf.HttpServerOptions.SSLInsecureSkipVerify,
		}
		return tls.Listen("tcp", targetPort, &config)

	} else if globalConf.HttpServerOptions.UseLE_SSL {

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("--> Using SSL LE (https)")

		GetLEState(&LE_MANAGER)

		config := tls.Config{
			GetCertificate: LE_MANAGER.GetCertificate,
		}
		return tls.Listen("tcp", targetPort, &config)

	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("--> Standard listener (http)")
		return net.Listen("tcp", targetPort)
	}
}

func handleDashboardRegistration() {
	if globalConf.UseDBAppConfigs {

		if DashService == nil {
			DashService = &HTTPDashboardHandler{}
			DashService.Init()
		}

		// connStr := buildConnStr("/register/node")

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Registering node.")
		if err := DashService.Register(); err != nil {
			log.Fatal("Registration failed: ", err)
		}

		startHeartBeat()
	}
}

func startHeartBeat() {
	if globalConf.UseDBAppConfigs {
		if DashService == nil {
			DashService = &HTTPDashboardHandler{}
			DashService.Init()
		}
		go DashService.StartBeating()
	}
}

func startDRL() {
	switch {
	case globalConf.ManagementNode,
		globalConf.EnableSentinelRateLImiter,
		globalConf.EnableRedisRollingLimiter:
		return
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialising distributed rate limiter")
	setupDRL()
	startRateLimitNotifications()
}

func listen(l, controlListener net.Listener, err error) {
	readTimeout := 120
	writeTimeout := 120
	targetPort := fmt.Sprintf("%s:%d", globalConf.ListenAddress, globalConf.ListenPort)
	if globalConf.HttpServerOptions.ReadTimeout > 0 {
		readTimeout = globalConf.HttpServerOptions.ReadTimeout
	}

	if globalConf.HttpServerOptions.WriteTimeout > 0 {
		writeTimeout = globalConf.HttpServerOptions.WriteTimeout
	}

	// Handle reload when SIGUSR2 is received
	if err != nil {
		// Listen on a TCP or a UNIX domain socket (TCP here).
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Setting up Server")

		// handle dashboard registration and nonces if available
		handleDashboardRegistration()

		startDRL()

		if !RPC_EmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, defaultRouter)
				getPolicies()
			}

			if globalConf.ControlAPIPort > 0 {
				loadAPIEndpoints(controlRouter)
			}
		}

		// Use a custom server so we can control keepalives
		if globalConf.HttpServerOptions.OverrideDefaults {
			defaultRouter.SkipClean(globalConf.HttpServerOptions.SkipURLCleaning)

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Custom gateway started")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(readTimeout) * time.Second,
				WriteTimeout: time.Duration(writeTimeout) * time.Second,
			}

			newServeMux := http.NewServeMux()
			newServeMux.Handle("/", defaultRouter)
			http.DefaultServeMux = newServeMux

			// Accept connections in a new goroutine.
			go s.Serve(l)

			if controlListener != nil {
				cs := &http.Server{
					ReadTimeout:  time.Duration(readTimeout) * time.Second,
					WriteTimeout: time.Duration(writeTimeout) * time.Second,
					Handler:      controlRouter,
				}
				go cs.Serve(controlListener)
			}

			displayConfig()
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway started (%s)", VERSION)

			go http.Serve(l, nil)

			if !RPC_EmergencyMode {
				newServeMux := http.NewServeMux()
				newServeMux.Handle("/", mainRouter)
				http.DefaultServeMux = newServeMux

				if controlListener != nil {
					go http.Serve(controlListener, controlRouter)
				}
			}

			displayConfig()
		}
	} else {
		// handle dashboard registration and nonces if available
		nonce := os.Getenv("TYK_SERVICE_NONCE")
		nodeID := os.Getenv("TYK_SERVICE_NODEID")
		if nonce == "" || nodeID == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("No nonce found, re-registering")
			handleDashboardRegistration()

		} else {
			NodeID = nodeID
			ServiceNonce = nonce
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("State recovered")

			os.Setenv("TYK_SERVICE_NONCE", "")
			os.Setenv("TYK_SERVICE_NODEID", "")
		}
		startDRL()

		// Resume accepting connections in a new goroutine.
		if !RPC_EmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, defaultRouter)
				getPolicies()
			}

			if globalConf.ControlAPIPort > 0 {
				loadAPIEndpoints(controlRouter)
			}

			startHeartBeat()
		}

		if globalConf.HttpServerOptions.OverrideDefaults {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(readTimeout) * time.Second,
				WriteTimeout: time.Duration(writeTimeout) * time.Second,
			}

			newServeMux := http.NewServeMux()
			newServeMux.Handle("/", defaultRouter)
			http.DefaultServeMux = newServeMux

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Custom gateway started")
			go s.Serve(l)

			if controlListener != nil {
				cs := &http.Server{
					ReadTimeout:  time.Duration(readTimeout) * time.Second,
					WriteTimeout: time.Duration(writeTimeout) * time.Second,
					Handler:      controlRouter,
				}
				go cs.Serve(controlListener)
			}

			displayConfig()
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway resumed (%s)", VERSION)

			go http.Serve(l, nil)

			if !RPC_EmergencyMode {
				newServeMux := http.NewServeMux()
				newServeMux.Handle("/", mainRouter)
				http.DefaultServeMux = newServeMux

				if controlListener != nil {
					go http.Serve(controlListener, controlRouter)
				}
			}

			displayConfig()
		}

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Resuming on", l.Addr())

	}
}
