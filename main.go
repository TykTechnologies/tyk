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

	apisMu   sync.RWMutex
	apisByID = map[string]*APISpec{}

	keyGen DefaultKeyGenerator

	policiesMu   sync.RWMutex
	policiesByID = map[string]Policy{}

	mainRouter    *mux.Router
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

// Create all globals and init connection handlers
func setupGlobals() {
	mainRouter = mux.NewRouter()
	controlRouter = mux.NewRouter()

	if config.Global.EnableAnalytics && config.Global.Storage.Type != "redis" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Panic("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	// Initialise our Host Checker
	healthCheckStore := &RedisClusterStorageManager{KeyPrefix: "host-checker:"}
	InitHostCheckManager(healthCheckStore)

	if config.Global.EnableAnalytics && analytics.Store == nil {
		config.Global.LoadIgnoredIPs()
		analyticsStore := RedisClusterStorageManager{KeyPrefix: "analytics-"}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Setting up analytics DB connection")

		analytics.Store = &analyticsStore
		analytics.Init()

		if config.Global.AnalyticsConfig.Type == "rpc" {
			log.Debug("Using RPC cache purge")

			purger := RPCPurger{Store: &analyticsStore}
			purger.Connect()
			analytics.Clean = &purger
			go analytics.Clean.PurgeLoop(10 * time.Second)
		}

	}

	// Load all the files that have the "error" prefix.
	templatesDir := filepath.Join(config.Global.TemplatePath, "error*")
	templates = template.Must(template.ParseGlob(templatesDir))

	// Set up global JSVM
	if config.Global.EnableJSVM {
		GlobalEventsJSVM.Init()
	}

	if config.Global.CoProcessOptions.EnableCoProcess {
		CoProcessInit()
	}

	// Get the notifier ready
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Notifier will not work in hybrid mode")
	mainNotifierStore := RedisClusterStorageManager{}
	mainNotifierStore.Connect()
	MainNotifier = RedisNotifier{&mainNotifierStore, RedisPubSubChannel}

	if config.Global.Monitor.EnableTriggerMonitors {
		h := &WebHookHandler{}
		if err := h.Init(config.Global.Monitor.Config); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to initialise monitor! ", err)
		} else {
			MonitoringHandler = h
		}
	}

	if config.Global.AnalyticsConfig.NormaliseUrls.Enabled {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Setting up analytics normaliser")
		config.Global.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()
	}

}

func buildConnStr(resource string) string {

	if config.Global.DBAppConfOptions.ConnectionString == "" && config.Global.DisableDashboardZeroConf {
		log.Fatal("Connection string is empty, failing.")
	}

	if !config.Global.DisableDashboardZeroConf && config.Global.DBAppConfOptions.ConnectionString == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Waiting for zeroconf signal...")
		for config.Global.DBAppConfOptions.ConnectionString == "" {
			time.Sleep(1 * time.Second)
		}
	}

	return config.Global.DBAppConfOptions.ConnectionString + resource
}

func getAPISpecs() []*APISpec {
	loader := APIDefinitionLoader{}
	var apiSpecs []*APISpec

	if config.Global.UseDBAppConfigs {

		connStr := buildConnStr("/system/apis")
		apiSpecs = loader.FromDashboardService(connStr, config.Global.NodeSecret)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Downloading API Configurations from Dashboard Service")
	} else if config.Global.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using RPC Configuration")

		apiSpecs = loader.FromRPC(config.Global.SlaveOptions.RPCKey)
	} else {
		apiSpecs = loader.FromDir(config.Global.AppPath)
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Printf("Detected %v APIs", len(apiSpecs))

	if config.Global.AuthOverride.ForceAuthProvider {
		for i := range apiSpecs {
			apiSpecs[i].AuthProvider = config.Global.AuthOverride.AuthProvider
		}
	}

	if config.Global.AuthOverride.ForceSessionProvider {
		for i := range apiSpecs {
			apiSpecs[i].SessionProvider = config.Global.AuthOverride.SessionProvider
		}
	}

	return apiSpecs
}

func getPolicies() {
	var pols map[string]Policy
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading policies")

	switch config.Global.Policies.PolicySource {
	case "service":
		if config.Global.Policies.PolicyConnectionString == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatal("No connection string or node ID present. Failing.")
		}
		connStr := config.Global.Policies.PolicyConnectionString
		connStr = connStr + "/system/policies"

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Using Policies from Dashboard Service")

		pols = LoadPoliciesFromDashboard(connStr, config.Global.NodeSecret, config.Global.Policies.AllowExplicitPolicyID)

	case "rpc":
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using Policies from RPC")
		pols = LoadPoliciesFromRPC(config.Global.SlaveOptions.RPCKey)
	default:
		// this is the only case now where we need a policy record name
		if config.Global.Policies.PolicyRecordName == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("No policy record name defined, skipping...")
			return
		}
		pols = LoadPoliciesFromFile(config.Global.Policies.PolicyRecordName)
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Infof("Policies found (%d total):", len(pols))
	for id := range pols {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Infof(" - %s", id)
	}

	if len(pols) > 0 {
		policiesMu.Lock()
		policiesByID = pols
		policiesMu.Unlock()
	}
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(muxer *mux.Router) {
	hostname := config.Global.HostName
	if config.Global.ControlAPIHostname != "" {
		hostname = config.Global.ControlAPIHostname
	}
	r := mux.NewRouter()
	muxer.PathPrefix("/tyk/").Handler(http.StripPrefix("/tyk",
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
		if tykAuthKey != config.Global.Secret {
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
	serverConfig.RedirectUriSeparator = config.Global.OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := getGlobalStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	osinServer := TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	muxer.Handle(apiAuthorizePath, checkIsAPIOwner(allowMethods(oauthHandlers.HandleGenerateAuthCodeData, "POST")))
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

func loadCustomMiddleware(spec *APISpec) ([]string, apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, apidef.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []apidef.MiddlewareDefinition{}
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
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range spec.CustomMiddleware.Post {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPostFuncs = append(mwPostFuncs, mwObj)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading custom POST-PROCESSOR middleware: ", mwObj.Name)
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
		globPath := filepath.Join(config.Global.MiddlewarePath, spec.APIID, folder.name, "*.js")
		paths, _ := filepath.Glob(globPath)
		for _, path := range paths {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Loading file middleware from ", path)

			mwDef := apidef.MiddlewareDefinition{}
			mwDef.Name = strings.Split(filepath.Base(path), ".")[0]
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware name ", mwDef.Name)
			mwDef.Path = path
			mwDef.RequireSession = strings.HasSuffix(mwDef.Name, "_with_session")
			if mwDef.RequireSession {
				switch folder.name {
				case "post_auth", "post":
					log.WithFields(logrus.Fields{
						"prefix": "main",
					}).Debug("-- Middleware requires session")
				default:
					log.WithFields(logrus.Fields{
						"prefix": "main",
					}).Warning("Middleware requires session, but isn't post-auth: ", mwDef.Name)
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

	return mwPaths, mwAuthCheckFunc, mwPreFuncs, mwPostFuncs, mwPostKeyAuthFuncs, mwDriver
}

func creeateResponseMiddlewareChain(spec *APISpec) {
	// Create the response processors

	responseChain := make([]TykResponseHandler, len(spec.ResponseProcessors))
	for i, processorDetail := range spec.ResponseProcessors {
		processor := responseProcessorByName(processorDetail.Name)
		if processor == nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("No such processor: ", processorDetail.Name)
			return
		}
		if err := processor.Init(processorDetail.Options, spec); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Failed to init processor: ", err)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = processor
	}
	spec.ResponseChain = responseChain
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
	return config.Global.AuthOverride.ForceAuthProvider &&
		config.Global.AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine
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
	if config.Global.EnableJSVM {
		GlobalEventsJSVM.Init()
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Preparing new router")
	mainRouter = mux.NewRouter()
	if config.Global.HttpServerOptions.OverrideDefaults {
		mainRouter.SkipClean(config.Global.HttpServerOptions.SkipURLCleaning)
	}

	if config.Global.ControlAPIPort == 0 {
		loadAPIEndpoints(mainRouter)
	}
	loadApps(specs, mainRouter)

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("API reload complete")

	// Unset these
	rpcEmergencyModeLoaded = false
	rpcEmergencyMode = false
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
		log.Info("Initiating reload")
		doReload()
		log.Info("Initiating coprocess reload")
		doCoprocessReload()

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
				log.Info("Reload queued")
				startReloadChan <- struct{}{}
				reloading = true
			} else {
				log.Info("Reload already queued")
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
	if config.Global.UseSentry {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Sentry support")
		hook, err := logrus_sentry.NewSentryHook(config.Global.SentryCode, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})

		hook.Timeout = 0

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Sentry hook active")
	}

	if config.Global.UseSyslog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Syslog support")
		hook, err := logrus_syslog.NewSyslogHook(config.Global.SyslogTransport,
			config.Global.SyslogNetworkAddr,
			syslog.LOG_INFO, "")

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Syslog hook active")
	}

	if config.Global.UseGraylog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Graylog support")
		hook := graylog.NewGraylogHook(config.Global.GraylogNetworkAddr,
			map[string]interface{}{"tyk-module": "gateway"})

		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Graylog hook active")
	}

	if config.Global.UseLogstash {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Logstash support")
		hook, err := logrus_logstash.NewHook(config.Global.LogstashTransport,
			config.Global.LogstashNetworkAddr,
			"tyk-gateway")

		if err == nil {
			log.Hooks.Add(hook)
			rawLog.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Logstash hook active")
	}

	if config.Global.UseRedisLog {
		hook := newRedisHook()
		log.Hooks.Add(hook)
		rawLog.Hooks.Add(hook)

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
		if err := config.Load(confPaths, &config.Global); err != nil {
			return err
		}
		afterConfSetup(&config.Global)
	}

	if config.Global.Storage.Type != "redis" {
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
			config.Global.ListenPort = portNum
		}
	}

	// Enable all the loggers
	setupLogger()

	if config.Global.PIDFileLocation == "" {
		config.Global.PIDFileLocation = "/var/run/tyk-gateway.pid"
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("PIDFile location set to: ", config.Global.PIDFileLocation)

	pidfile.SetPidfilePath(config.Global.PIDFileLocation)
	if err := pidfile.Write(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Failed to write PIDFile: ", err)
	}

	getHostDetails()
	setupInstrumentation(arguments)

	if config.Global.HttpServerOptions.UseLE_SSL {
		go StartPeriodicStateBackup(&LE_MANAGER)
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
	GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	conf.EventTriggers = InitGenericEventHandlers(conf.EventHandlers)
}

var hostDetails struct {
	Hostname string
	PID      int
}

func getHostDetails() {
	var err error
	if hostDetails.PID, err = pidfile.Read(); err != nil {
		log.Error("Failed ot get host pid: ", err)
	}
	if hostDetails.Hostname, err = os.Hostname(); err != nil {
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

func getGlobalStorageHandler(keyPrefix string, hashKeys bool) StorageHandler {
	if config.Global.SlaveOptions.UseRPC {
		return &RPCStorageHandler{KeyPrefix: keyPrefix, HashKeys: hashKeys, UserKey: config.Global.SlaveOptions.APIKey, Address: config.Global.SlaveOptions.ConnectionString}
	}
	return &RedisClusterStorageManager{KeyPrefix: keyPrefix, HashKeys: hashKeys}
}

func main() {
	arguments := getCmdArguments()
	NodeID = "solo-" + uuid.NewV4().String()

	amForked := false

	onFork := func() {
		if config.Global.UseDBAppConfigs {
			log.Info("Stopping heartbeat")
			DashService.StopBeating()
			log.Info("Waiting to de-register")
			time.Sleep(10 * time.Second)

			os.Setenv("TYK_SERVICE_NONCE", ServiceNonce)
			os.Setenv("TYK_SERVICE_NODEID", NodeID)
		}
	}

	l, _ := goagain.Listener(onFork)
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

		if config.Global.ControlAPIPort > 0 {
			if controlListener, err = generateListener(config.Global.ControlAPIPort); err != nil {
				log.WithFields(logrus.Fields{
					"prefix": "main",
				}).Fatalf("Error starting control API listener: %s", err)
			}
		}

		listen(l, controlListener, goAgainErr)
	} else {
		listen(l, controlListener, nil)

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

		if config.Global.UseDBAppConfigs {
			log.Info("Stopping heartbeat...")
			DashService.StopBeating()
			time.Sleep(2 * time.Second)
			DashService.DeRegister()
		}

		log.Info("Terminating.")
	} else {
		log.Info("Terminated from fork.")
	}

	time.Sleep(time.Second)
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

		mainRouter.HandleFunc("/debug/pprof/{_:.*}", pprof_http.Index)
	}

	// Set up a default org manager so we can traverse non-live paths
	if !config.Global.SupressDefaultOrgStore {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Initialising default org store")
		//DefaultOrgStore.Init(&RedisClusterStorageManager{KeyPrefix: "orgkey."})
		DefaultOrgStore.Init(getGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(getGlobalStorageHandler(CloudHandler, "orgkey.", false))
		DefaultQuotaStore.Init(getGlobalStorageHandler("orgkey.", false))
	}

	if config.Global.ControlAPIPort == 0 {
		loadAPIEndpoints(mainRouter)
	}

	// Start listening for reload messages
	if !config.Global.SuppressRedisSignalReload {
		go startPubSubLoop()
	}

	if config.Global.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Starting RPC reload listener")
		RPCListener = RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			UserKey:          config.Global.SlaveOptions.APIKey,
			Address:          config.Global.SlaveOptions.ConnectionString,
			SuppressRegister: true,
		}
		RPCListener.Connect()
		go rpcReloadLoop(config.Global.SlaveOptions.RPCKey)
		go RPCListener.StartRPCLoopCheck(config.Global.SlaveOptions.RPCKey)
	}

	// 1s is the minimum amount of time between hot reloads. The
	// interval counts from the start of one reload to the next.
	go reloadLoop(time.Tick(time.Second))
	go reloadQueueLoop()
}

func generateListener(listenPort int) (net.Listener, error) {
	listenAddress := config.Global.ListenAddress
	if listenPort == 0 {
		listenPort = config.Global.ListenPort
	}

	targetPort := fmt.Sprintf("%s:%d", listenAddress, listenPort)

	if config.Global.HttpServerOptions.UseSSL {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("--> Using SSL (https)")
		certs := make([]tls.Certificate, len(config.Global.HttpServerOptions.Certificates))
		certNameMap := make(map[string]*tls.Certificate)
		for i, certData := range config.Global.HttpServerOptions.Certificates {
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
			ServerName:         config.Global.HttpServerOptions.ServerName,
			MinVersion:         config.Global.HttpServerOptions.MinVersion,
			InsecureSkipVerify: config.Global.HttpServerOptions.SSLInsecureSkipVerify,
		}
		return tls.Listen("tcp", targetPort, &config)

	} else if config.Global.HttpServerOptions.UseLE_SSL {

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
	if !config.Global.UseDBAppConfigs {
		return
	}

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

	go DashService.StartBeating()
}

func startDRL() {
	switch {
	case config.Global.ManagementNode,
		config.Global.EnableSentinelRateLImiter,
		config.Global.EnableRedisRollingLimiter:
		return
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialising distributed rate limiter")
	setupDRL()
	startRateLimitNotifications()
}

// mainHandler's only purpose is to allow mainRouter to be dynamically replaced
type mainHandler struct{}

func (_ mainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mainRouter.ServeHTTP(w, r)
}

func listen(l, controlListener net.Listener, err error) {
	readTimeout := 120
	writeTimeout := 120
	targetPort := fmt.Sprintf("%s:%d", config.Global.ListenAddress, config.Global.ListenPort)
	if config.Global.HttpServerOptions.ReadTimeout > 0 {
		readTimeout = config.Global.HttpServerOptions.ReadTimeout
	}

	if config.Global.HttpServerOptions.WriteTimeout > 0 {
		writeTimeout = config.Global.HttpServerOptions.WriteTimeout
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

		if !rpcEmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, mainRouter)
				getPolicies()
			}

			if config.Global.ControlAPIPort > 0 {
				loadAPIEndpoints(controlRouter)
			}
		}

		// Use a custom server so we can control keepalives
		if config.Global.HttpServerOptions.OverrideDefaults {
			mainRouter.SkipClean(config.Global.HttpServerOptions.SkipURLCleaning)

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
				Handler:      mainHandler{},
			}

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
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway started (%s)", VERSION)

			go http.Serve(l, mainHandler{})

			if !rpcEmergencyMode {
				if controlListener != nil {
					go http.Serve(controlListener, controlRouter)
				}
			}
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
		if !rpcEmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, mainRouter)
				getPolicies()
			}

			if config.Global.ControlAPIPort > 0 {
				loadAPIEndpoints(controlRouter)
			}

			if config.Global.UseDBAppConfigs {
				go DashService.StartBeating()
			}
		}

		if config.Global.HttpServerOptions.OverrideDefaults {
			mainRouter.SkipClean(config.Global.HttpServerOptions.SkipURLCleaning)

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(readTimeout) * time.Second,
				WriteTimeout: time.Duration(writeTimeout) * time.Second,
				Handler:      mainHandler{},
			}

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
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway resumed (%s)", VERSION)

			go http.Serve(l, mainHandler{})

			if !rpcEmergencyMode {
				if controlListener != nil {
					go http.Serve(controlListener, controlRouter)
				}
			}
		}

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Resuming on", l.Addr())
	}
	address := config.Global.ListenAddress
	if config.Global.ListenAddress == "" {
		address = "(open interface)"
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on address: ", address)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on port: ", config.Global.ListenPort)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> PID: ", hostDetails.PID)
}
