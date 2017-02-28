package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io/ioutil"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	pprof_http "net/http/pprof"

	logger "github.com/TykTechnologies/tyk/log"

	"github.com/docopt/docopt.go"
	"github.com/facebookgo/pidfile"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/lonelycode/gorpc"
	"github.com/lonelycode/logrus-graylog-hook"
	osin "github.com/lonelycode/osin"
	"github.com/rs/cors"
	"rsc.io/letsencrypt"

	"github.com/TykTechnologies/goagain"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/logrus-logstash-hook"
	logrus_syslog "github.com/TykTechnologies/logrus/hooks/syslog"
	"github.com/TykTechnologies/logrus_sentry"
	"github.com/TykTechnologies/tyk/apidef"
)

var (
	log                      = logger.Get()
	config                   = Config{}
	templates                = &template.Template{}
	analytics                = RedisAnalyticsHandler{}
	GlobalEventsJSVM         = &JSVM{}
	cpuProfFile              *os.File
	memProfFile              *os.File
	doHTTPProfile            bool
	doMemoryProfile          bool
	doCpuProfile             bool
	Policies                 = map[string]Policy{}
	MainNotifier             = RedisNotifier{}
	DefaultOrgStore          = DefaultSessionManager{}
	DefaultQuotaStore        = DefaultSessionManager{}
	FallbackKeySesionManager = SessionHandler(&DefaultSessionManager{})
	MonitoringHandler        TykEventHandler
	RPCListener              = RPCStorageHandler{}
	argumentsBackup          map[string]interface{}
	DashService              DashboardServiceSender

	ApiSpecRegister map[string]*APISpec
	keyGen          = DefaultKeyGenerator{}

	mainRouter    *mux.Router
	defaultRouter *mux.Router
	controlRouter *mux.Router
	LE_MANAGER    letsencrypt.Manager
	LE_FIRSTRUN   bool

	NodeID string

	runningTests = false

	systemError = []byte(`{"status": "system error, please contact administrator"}`)
)

const (
	// Generic system error
	oauthPrefix = "oauth-data."
)

// Display configuration options
func displayConfig() {
	address := config.ListenAddress
	if config.ListenAddress == "" {
		address = "(open interface)"
	}
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on address: ", address)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> Listening on port: ", config.ListenPort)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("--> PID: ", HostDetails.PID)
}

func getHostName() string {
	hName := config.HostName
	if config.HostName == "" {
		hName = ""
	}

	return hName
}

func pingTest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello Tiki")
}

// Create all globals and init connection handlers
func setupGlobals() {
	mainRouter = mux.NewRouter()
	if getHostName() != "" {
		defaultRouter = mainRouter.Host(getHostName()).Subrouter()
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Hostname set: ", getHostName())
	} else {
		defaultRouter = mainRouter
	}

	controlRouter = mux.NewRouter()

	if config.EnableAnalytics && config.Storage.Type != "redis" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Panic("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	// Initialise our Host Checker
	HealthCheckStore := &RedisClusterStorageManager{KeyPrefix: "host-checker:"}
	InitHostCheckManager(HealthCheckStore)

	if config.EnableAnalytics {
		config.loadIgnoredIPs()
		AnalyticsStore := RedisClusterStorageManager{KeyPrefix: "analytics-"}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Setting up analytics DB connection")

		analytics = RedisAnalyticsHandler{
			Store: &AnalyticsStore,
		}

		analytics.Init()

		if config.AnalyticsConfig.Type == "rpc" {
			log.Debug("Using RPC cache purge")

			purger := RPCPurger{Store: &AnalyticsStore}
			purger.Connect()
			analytics.Clean = &purger
			go analytics.Clean.PurgeLoop(10 * time.Second)
		}

	}

	// Load all the files that have the "error" prefix.
	templatesDir := filepath.Join(config.TemplatePath, "error*")
	templates = template.Must(template.ParseGlob(templatesDir))

	// Set up global JSVM
	if config.EnableJSVM {
		GlobalEventsJSVM.Init(config.TykJSPath)
	}

	if config.CoProcessOptions.EnableCoProcess {
		CoProcessInit()
	}

	// Get the notifier ready
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Notifier will not work in hybrid mode")
	MainNotifierStore := RedisClusterStorageManager{}
	MainNotifierStore.Connect()
	MainNotifier = RedisNotifier{&MainNotifierStore, RedisPubSubChannel}

	if config.Monitor.EnableTriggerMonitors {
		var err error
		MonitoringHandler, err = (&WebHookHandler{}).New(config.Monitor.Config)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to initialise monitor! ", err)
		}
	}

	if config.AnalyticsConfig.NormaliseUrls.Enabled {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Setting up analytics normaliser")
		config.AnalyticsConfig.NormaliseUrls.compiledPatternSet = InitNormalisationPatterns()
	}

}

func waitForZeroConf() {
	if config.DBAppConfOptions.ConnectionString == "" {
		time.Sleep(1 * time.Second)
		waitForZeroConf()
	}
}

func buildConnStr(resource string) string {

	if config.DBAppConfOptions.ConnectionString == "" && config.DisableDashboardZeroConf {
		log.Fatal("Connection string is empty, failing.")
		return ""
	}

	if !config.DisableDashboardZeroConf && config.DBAppConfOptions.ConnectionString == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Waiting for zeroconf signal...")
		waitForZeroConf()
	}

	connStr := config.DBAppConfOptions.ConnectionString
	connStr = connStr + resource
	return connStr
}

// Pull API Specs from configuration
var APILoader = APIDefinitionLoader{}

func getAPISpecs() []*APISpec {
	var APISpecs []*APISpec

	if config.UseDBAppConfigs {

		connStr := buildConnStr("/system/apis")
		APISpecs = APILoader.LoadDefinitionsFromDashboardService(connStr, config.NodeSecret)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Downloading API Configurations from Dashboard Service")
	} else if config.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using RPC Configuration")

		APISpecs = APILoader.LoadDefinitionsFromRPC(config.SlaveOptions.RPCKey)
	} else {

		APISpecs = APILoader.LoadDefinitions(config.AppPath)
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Printf("Detected %v APIs", len(APISpecs))

	if config.AuthOverride.ForceAuthProvider {
		for i := range APISpecs {
			APISpecs[i].AuthProvider = config.AuthOverride.AuthProvider

		}
	}

	if config.AuthOverride.ForceSessionProvider {
		for i := range APISpecs {
			APISpecs[i].SessionProvider = config.AuthOverride.SessionProvider
		}
	}

	return APISpecs
}

func getPolicies() {
	pols := make(map[string]Policy)
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Loading policies")

	if config.Policies.PolicySource == "service" {
		if config.Policies.PolicyConnectionString != "" {
			connStr := config.Policies.PolicyConnectionString
			connStr = connStr + "/system/policies"

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Using Policies from Dashboard Service")

			pols = LoadPoliciesFromDashboard(connStr, config.NodeSecret, config.Policies.AllowExplicitPolicyID)

		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatal("No connection string or node ID present. Failing.")
		}

	} else if config.Policies.PolicySource == "rpc" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using Policies from RPC")
		pols = LoadPoliciesFromRPC(config.SlaveOptions.RPCKey)
	} else {
		// this is the only case now where we need a policy record name
		if config.Policies.PolicyRecordName == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("No policy record name defined, skipping...")
			return
		}
		pols = LoadPoliciesFromFile(config.Policies.PolicyRecordName)
	}

	if len(pols) > 0 {
		Policies = pols
		return
	}
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(Muxer *mux.Router) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialising Tyk REST API Endpoints")

	apiMuxer := Muxer
	if config.EnableAPISegregation {
		if config.ControlAPIHostname != "" {
			apiMuxer = Muxer.Host(config.ControlAPIHostname).Subrouter()
		}
	}

	// set up main API handlers
	apiMuxer.HandleFunc("/tyk/reload/group", CheckIsAPIOwner(InstrumentationMW(groupResetHandler)))
	apiMuxer.HandleFunc("/tyk/reload/", CheckIsAPIOwner(InstrumentationMW(resetHandler)))

	if !IsRPCMode() {
		apiMuxer.HandleFunc("/tyk/org/keys/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(orgHandler)))
		apiMuxer.HandleFunc("/tyk/keys/policy/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(policyUpdateHandler)))
		apiMuxer.HandleFunc("/tyk/keys/create", CheckIsAPIOwner(InstrumentationMW(createKeyHandler)))
		apiMuxer.HandleFunc("/tyk/apis/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(apiHandler)))
		apiMuxer.HandleFunc("/tyk/health/", CheckIsAPIOwner(InstrumentationMW(healthCheckhandler)))
		apiMuxer.HandleFunc("/tyk/oauth/clients/create", CheckIsAPIOwner(InstrumentationMW(createOauthClient)))
		apiMuxer.HandleFunc("/tyk/oauth/refresh/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(invalidateOauthRefresh)))
		apiMuxer.HandleFunc("/tyk/cache/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(invalidateCacheHandler)))
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Node is slaved, REST API minimised")
	}

	apiMuxer.HandleFunc("/tyk/keys/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(keyHandler)))
	apiMuxer.HandleFunc("/tyk/oauth/clients/{rest:.*}", CheckIsAPIOwner(InstrumentationMW(oAuthClientHandler)))

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Loaded API Endpoints")
}

// CheckIsAPIOwner will ensure that the accessor of the tyk API has the
// correct security credentials - this is a shared secret between the
// client and the owner and is set in the tyk.conf file. This should
// never be made public!
func CheckIsAPIOwner(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get("X-Tyk-Authorization")
		if tykAuthKey != config.Secret {
			// Error
			log.Warning("Attempted administrative access with invalid or missing key!")

			responseMessage := createError("Forbidden")
			w.WriteHeader(403)
			w.Write(responseMessage)
			return
		}

		handler(w, r)

	}
}

func generateOAuthPrefix(apiID string) string {
	return oauthPrefix + apiID + "."
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec *APISpec, Muxer *mux.Router, test bool) *OAuthManager {
	apiAuthorizePath := spec.Proxy.ListenPath + "tyk/oauth/authorize-client/"
	clientAuthPath := spec.Proxy.ListenPath + "oauth/authorize/"
	clientAccessPath := spec.Proxy.ListenPath + "oauth/token/"

	serverConfig := osin.NewServerConfig()
	serverConfig.ErrorStatusCode = 403
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes
	serverConfig.RedirectUriSeparator = config.OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := GetGlobalStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	if test {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("Adding test clients")

		testPolicy := Policy{}
		testPolicy.Rate = 100
		testPolicy.Per = 1
		testPolicy.QuotaMax = -1
		testPolicy.QuotaRenewalRate = 1000000000

		Policies["TEST-4321"] = testPolicy

		var redirectURI string
		// If separator is not set that means multiple redirect uris not supported
		if config.OauthRedirectUriSeparator == "" {
			redirectURI = "http://client.oauth.com"

			// If separator config is set that means multiple redirect uris are supported
		} else {
			redirectURI = strings.Join([]string{"http://client.oauth.com", "http://client2.oauth.com", "http://client3.oauth.com"}, config.OauthRedirectUriSeparator)
		}
		testClient := OAuthClient{
			ClientID:          "1234",
			ClientSecret:      "aabbccdd",
			ClientRedirectURI: redirectURI,
			PolicyID:          "TEST-4321",
		}
		osinStorage.SetClient(testClient.ClientID, &testClient, false)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("Test client added")
	}

	osinServer := TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	Muxer.HandleFunc(apiAuthorizePath, CheckIsAPIOwner(oauthHandlers.HandleGenerateAuthCodeData))
	Muxer.HandleFunc(clientAuthPath, oauthHandlers.HandleAuthorizePassthrough)
	Muxer.HandleFunc(clientAccessPath, oauthHandlers.HandleAccessRequest)

	return &oauthManager
}

func addBatchEndpoint(spec *APISpec, Muxer *mux.Router) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Batch requests enabled for API")
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	batchHandler := BatchRequestHandler{API: spec}
	Muxer.HandleFunc(apiBatchPath, batchHandler.HandleBatchRequest)
}

func loadCustomMiddleware(referenceSpec *APISpec) ([]string, apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, []apidef.MiddlewareDefinition, apidef.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc apidef.MiddlewareDefinition
	mwPreFuncs := []apidef.MiddlewareDefinition{}
	mwPostFuncs := []apidef.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []apidef.MiddlewareDefinition{}
	mwDriver := apidef.OttoDriver

	// Set AuthCheck hook
	if referenceSpec.APIDefinition.CustomMiddleware.AuthCheck.Name != "" {
		mwAuthCheckFunc = referenceSpec.APIDefinition.CustomMiddleware.AuthCheck
		if referenceSpec.APIDefinition.CustomMiddleware.AuthCheck.Path != "" {
			// Feed a JS file to Otto
			mwPaths = append(mwPaths, referenceSpec.APIDefinition.CustomMiddleware.AuthCheck.Path)
		}
	}

	// Load from the configuration
	for _, mwObj := range referenceSpec.APIDefinition.CustomMiddleware.Pre {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPreFuncs = append(mwPreFuncs, mwObj)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range referenceSpec.APIDefinition.CustomMiddleware.Post {
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
		dirPath := filepath.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, folder.name)
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
	if referenceSpec.APIDefinition.CustomMiddleware.Driver != "" {
		mwDriver = referenceSpec.APIDefinition.CustomMiddleware.Driver
	}

	// Load PostAuthCheck hooks
	for _, mwObj := range referenceSpec.APIDefinition.CustomMiddleware.PostKeyAuth {
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

	responseChain := make([]TykResponseHandler, len(referenceSpec.APIDefinition.ResponseProcessors))
	for i, processorDetail := range referenceSpec.APIDefinition.ResponseProcessors {
		processorType, err := GetResponseProcessorByName(processorDetail.Name)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to load processor! ", err)
			return
		}
		processor, _ := processorType.New(processorDetail.Options, referenceSpec)
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

func IsRPCMode() bool {
	return config.AuthOverride.ForceAuthProvider &&
		config.AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine
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
	if config.UseRedisLog {
		log.WithFields(logrus.Fields{
			"prefix":      "gateway",
			"user_ip":     "--",
			"server_name": "--",
			"user_id":     "--",
			"org_id":      spec.APIDefinition.OrgID,
			"api_id":      spec.APIDefinition.APIID,
		}).Info("Loaded: ", spec.APIDefinition.Name)
	}

}

func RPCReloadLoop(rpcKey string) {
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
	if config.EnableJSVM {
		GlobalEventsJSVM.Init(config.TykJSPath)
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Preparing new router")
	newRouter := mux.NewRouter()
	mainRouter = newRouter

	var newMuxes *mux.Router
	if getHostName() != "" {
		newMuxes = newRouter.Host(getHostName()).Subrouter()
	} else {
		newMuxes = newRouter
	}

	if config.ControlAPIPort == 0 {
		loadAPIEndpoints(newMuxes)
	}
	loadApps(specs, newMuxes)

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

var (
	// reloadInterval is the amount of time to sleep after every
	// reload. In other words, a reload will run at most once every
	// reloadInterval.
	reloadInterval = 1 * time.Second

	// reloadChan is a queue for incoming reload requests. At most,
	// we want to have one reload running and one queued. If one is
	// already queued, any reload requests should do nothing as a
	// reload is already going to start at some point. Hence, buffer
	// of size 1.
	// If the queued func is non-nil, it is called once the reload
	// is done.
	reloadChan = make(chan func(), 1)
)

func reloadLoop() {
	for fn := range reloadChan {
		log.Info("Initiating reload")
		doReload()
		log.Info("Initiating coprocess reload")
		doCoprocessReload()

		if fn != nil {
			fn()
		}
		time.Sleep(reloadInterval)
	}
}

// ReloadURLStructure will create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one, this enables a
// reconfiguration to take place without stopping any requests from being handled.
// It returns true if it was queued, or false if it wasn't.
func ReloadURLStructure(fn func()) bool {
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
	if config.UseSentry {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Sentry support")
		hook, err := logrus_sentry.NewSentryHook(config.SentryCode, []logrus.Level{
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

	if config.UseSyslog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Syslog support")
		hook, err := logrus_syslog.NewSyslogHook(config.SyslogTransport,
			config.SyslogNetworkAddr,
			syslog.LOG_INFO, "")

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Syslog hook active")
	}

	if config.UseGraylog {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Graylog support")
		hook := graylog.NewGraylogHook(config.GraylogNetworkAddr,
			map[string]interface{}{"tyk-module": "gateway"})

		log.Hooks.Add(hook)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Graylog hook active")
	}

	if config.UseLogstash {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling Logstash support")
		hook, err := logrus_logstash.NewHook(config.LogstashTransport,
			config.LogstashNetworkAddr,
			"tyk-gateway")

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Logstash hook active")
	}

	if config.UseRedisLog {
		redisHook := NewRedisHook()
		log.Hooks.Add(redisHook)

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Redis log hook active")
	}

}

func initialiseSystem(arguments map[string]interface{}) {

	// Enable command mode
	for _, opt := range commandModeOptions {
		v := arguments[opt]
		if v == true {
			HandleCommandModeArgs(arguments)
			os.Exit(0)
		}
		if v != nil && v != false {
			HandleCommandModeArgs(arguments)
			os.Exit(0)
		}
	}

	if runningTests && os.Getenv("TYK_LOGLEVEL") == "" {
		// `go test` without TYK_LOGLEVEL set defaults to no log
		// output
		log.Level = logrus.ErrorLevel
		log.Out = ioutil.Discard
		gorpc.SetErrorLogger(func(string, ...interface{}) {})
	} else if dbg, _ := arguments["--debug"]; dbg == true {
		log.Level = logrus.DebugLevel
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling debug-level output")
	}

	filename := "/etc/tyk/tyk.conf"
	value, _ := arguments["--conf"]
	if value != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debugf("Using %s for configuration", value.(string))
		filename = arguments["--conf"].(string)
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("No configuration file defined, will try to use default (./tyk.conf)")
	}

	loadConfig(filename, &config)

	if config.Storage.Type != "redis" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatal("Redis connection details not set, please ensure that the storage type is set to Redis and that the connection parameters are correct.")
	}

	setupGlobals()

	port, _ := arguments["--port"]
	if port != nil {
		portNum, err := strconv.Atoi(port.(string))
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Port specified in flags must be a number: ", err)
		} else {
			config.ListenPort = portNum
		}
	}

	doMemoryProfile, _ = arguments["--memprofile"].(bool)
	doCpuProfile, _ = arguments["--cpuprofile"].(bool)
	doHTTPProfile, _ = arguments["--httpprofile"].(bool)

	// Enable all the loggers
	setupLogger()

	if config.PIDFileLocation == "" {
		config.PIDFileLocation = "/var/run/tyk-gateway.pid"
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("PIDFile location set to: ", config.PIDFileLocation)

	pidfile.SetPidfilePath(config.PIDFileLocation)
	if err := pidfile.Write(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Failed to write PIDFile: ", err)
	}

	GetHostDetails()

	//doInstrumentation, _ := arguments["--log-instrumentation"].(bool)
	//SetupInstrumentation(doInstrumentation)
	SetupInstrumentation(true)

	go reloadLoop()

	go StartPeriodicStateBackup(&LE_MANAGER)
}

type AuditHostDetails struct {
	Hostname string
	PID      int
}

var HostDetails AuditHostDetails

func GetHostDetails() {
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
		--org-id=><id>               Assign the API Defintition to this org_id (required with create)
		--upstream-target=<url>      Set the upstream target for the definition
		--as-mock                    Creates the API as a mock based on example fields
		--for-api=<path>             Adds blueprint to existing API Defintition as version
		--as-version=<version>       The version number to use when inserting
		--log-instrumentation        Output instrumentation data to stdout
	`

	arguments, err := docopt.Parse(usage, nil, true, VERSION, false)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("Error while parsing arguments: ", err)
	}

	argumentsBackup = arguments
	return arguments
}

var KeepaliveRunning bool

func StartRPCKeepaliveWatcher(engine *RPCStorageHandler) {
	if KeepaliveRunning {
		return
	}

	go func() {
		log.WithFields(logrus.Fields{
			"prefix": "RPC Conn Mgr",
		}).Info("[RPC Conn Mgr] Starting keepalive watcher...")
		for {
			KeepaliveRunning = true
			RPCKeepAliveCheck(engine)
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

func GetGlobalLocalStorageHandler(KeyPrefix string, hashKeys bool) StorageHandler {
	return &RedisClusterStorageManager{KeyPrefix: KeyPrefix, HashKeys: hashKeys}
}

func GetGlobalLocalCacheStorageHandler(KeyPrefix string, hashKeys bool) StorageHandler {
	return &RedisClusterStorageManager{KeyPrefix: KeyPrefix, HashKeys: hashKeys, IsCache: true}
}

func GetGlobalStorageHandler(KeyPrefix string, hashKeys bool) StorageHandler {
	if config.SlaveOptions.UseRPC {
		return &RPCStorageHandler{KeyPrefix: KeyPrefix, HashKeys: hashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	}
	return &RedisClusterStorageManager{KeyPrefix: KeyPrefix, HashKeys: hashKeys}
}

// Handles pre-fork actions if we get a SIGHUP2
var amForked bool

func onFork() {
	if config.UseDBAppConfigs {
		log.Info("Stopping heartbeat")
		DashService.StopBeating()

		log.Info("Waiting to de-register")
		time.Sleep(10 * time.Second)

		os.Setenv("TYK_SERVICE_NONCE", ServiceNonce)
		os.Setenv("TYK_SERVICE_NODEID", NodeID)
	}

	amForked = true
}

func main() {
	arguments := getCmdArguments()
	NodeID = generateRandomNodeID()
	l, goAgainErr := goagain.Listener(onFork)
	controlListener, goAgainErr := goagain.Listener(onFork)

	initialiseSystem(arguments)
	start()

	if goAgainErr != nil {
		var err error
		if l, err = generateListener(l, "", 0); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatalf("Error starting listener: %s", err)
		}

		if config.ControlAPIPort > 0 {
			if controlListener, err = generateListener(controlListener, "", config.ControlAPIPort); err != nil {
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
		if err := goagain.Kill(); nil != err {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatalln(err)
		}
	}

	// Block the main goroutine awaiting signals.
	if _, err := goagain.Wait(l); nil != err {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Fatalln(err)
	}

	// Do whatever's necessary to ensure a graceful exit
	// In this case, we'll simply stop listening and wait one second.
	if err := l.Close(); nil != err {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Listen handler exit: ", err)
	}

	if !amForked {
		log.Info("Stop signal received.")

		if config.UseDBAppConfigs {
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

func start() {
	if doMemoryProfile {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Memory profiling active")
		var err error
		if memProfFile, err = os.Create("tyk.mprof"); err != nil {
			panic(err)
		}
		defer memProfFile.Close()
	}
	if doCpuProfile {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Cpu profiling active")
		var err error
		if cpuProfFile, err = os.Create("tyk.prof"); err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(cpuProfFile)
		defer pprof.StopCPUProfile()
	}

	if doHTTPProfile {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Adding pprof endpoints")

		defaultRouter.HandleFunc("/debug/pprof/{rest:.*}", http.HandlerFunc(pprof_http.Index))
		defaultRouter.HandleFunc("/debug/pprof/cmdline", http.HandlerFunc(pprof_http.Cmdline))
		defaultRouter.HandleFunc("/debug/pprof/profile", http.HandlerFunc(pprof_http.Profile))
		defaultRouter.HandleFunc("/debug/pprof/symbol", http.HandlerFunc(pprof_http.Symbol))
		defaultRouter.HandleFunc("/debug/pprof/trace", http.HandlerFunc(pprof_http.Trace))
	}

	// Set up a default org manager so we can traverse non-live paths
	if !config.SupressDefaultOrgStore {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Initialising default org store")
		//DefaultOrgStore.Init(&RedisClusterStorageManager{KeyPrefix: "orgkey."})
		DefaultOrgStore.Init(GetGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(GetGlobalStorageHandler(CloudHandler, "orgkey.", false))
		DefaultQuotaStore.Init(GetGlobalStorageHandler("orgkey.", false))
	}

	if config.ControlAPIPort == 0 {
		loadAPIEndpoints(defaultRouter)
	}

	// Start listening for reload messages
	if !config.SuppressRedisSignalReload {
		go StartPubSubLoop()
	}

	if config.SlaveOptions.UseRPC {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Starting RPC reload listener")
		RPCListener = RPCStorageHandler{
			KeyPrefix:        "rpc.listener.",
			UserKey:          config.SlaveOptions.APIKey,
			Address:          config.SlaveOptions.ConnectionString,
			SuppressRegister: true,
		}
		RPCListener.Connect()
		go RPCReloadLoop(config.SlaveOptions.RPCKey)
		go RPCListener.StartRPCLoopCheck(config.SlaveOptions.RPCKey)
	}

}

func generateListener(l net.Listener, listenAddress string, listenPort int) (net.Listener, error) {
	if listenAddress == "" {
		listenAddress = config.ListenAddress
	}
	if listenPort == 0 {
		listenPort = config.ListenPort
	}

	targetPort := fmt.Sprintf("%s:%d", listenAddress, listenPort)

	if config.HttpServerOptions.UseSSL {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("--> Using SSL (https)")
		certs := make([]tls.Certificate, len(config.HttpServerOptions.Certificates))
		certNameMap := make(map[string]*tls.Certificate)
		for i, certData := range config.HttpServerOptions.Certificates {
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
			Certificates:      certs,
			NameToCertificate: certNameMap,
			ServerName:        config.HttpServerOptions.ServerName,
			MinVersion:        config.HttpServerOptions.MinVersion,
		}
		return tls.Listen("tcp", targetPort, &config)

	} else if config.HttpServerOptions.UseLE_SSL {

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
	if config.UseDBAppConfigs {

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
	if config.UseDBAppConfigs {
		if DashService == nil {
			DashService = &HTTPDashboardHandler{}
			DashService.Init()
		}
		go DashService.StartBeating()
	}
}

func StartDRL() {
	if !config.EnableSentinelRateLImiter && !config.EnableRedisRollingLimiter {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Initialising distributed rate limiter")
		SetupDRL()
		StartRateLimitNotifications()
	}
}

func listen(l net.Listener, controlListener net.Listener, err error) {
	ReadTimeout := 120
	WriteTimeout := 120
	targetPort := fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort)
	if config.HttpServerOptions.ReadTimeout > 0 {
		ReadTimeout = config.HttpServerOptions.ReadTimeout
	}

	if config.HttpServerOptions.WriteTimeout > 0 {
		WriteTimeout = config.HttpServerOptions.WriteTimeout
	}

	// Handle reload when SIGUSR2 is received
	if nil != err {
		// Listen on a TCP or a UNIX domain socket (TCP here).
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Setting up Server")

		// handle dashboard registration and nonces if available
		handleDashboardRegistration()

		StartDRL()

		if !RPC_EmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, defaultRouter)
				getPolicies()

				if config.ControlAPIPort > 0 {
					loadAPIEndpoints(controlRouter)
				}
			}
		}

		// Use a custom server so we can control keepalives
		if config.HttpServerOptions.OverrideDefaults {
			defaultRouter.SkipClean(config.HttpServerOptions.SkipURLCleaning)

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Custom gateway started")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(WriteTimeout) * time.Second,
				Handler:      defaultRouter,
			}

			// Accept connections in a new goroutine.
			go s.Serve(l)
			displayConfig()
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway started (%v)", VERSION)
			if !RPC_EmergencyMode {
				http.Handle("/", mainRouter)
			}
			go http.Serve(l, nil)

			if controlListener != nil {
				go http.Serve(controlListener, controlRouter)
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
		StartDRL()

		// Resume accepting connections in a new goroutine.
		if !RPC_EmergencyMode {
			specs := getAPISpecs()
			if specs != nil {
				loadApps(specs, defaultRouter)
				getPolicies()
			}

			startHeartBeat()
		}

		if config.HttpServerOptions.OverrideDefaults {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(WriteTimeout) * time.Second,
				Handler:      defaultRouter,
			}

			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("Custom gateway started")
			go s.Serve(l)
			displayConfig()
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Printf("Gateway resumed (%v)", VERSION)
			displayConfig()
			http.Handle("/", mainRouter)
			go http.Serve(l, nil)
		}

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Resuming on", l.Addr())

	}
}
