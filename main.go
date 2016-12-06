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
	"path"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/goagain"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/logrus-logstash-hook"
	logrus_syslog "github.com/TykTechnologies/logrus/hooks/syslog"
	"github.com/TykTechnologies/logrus_sentry"
	"github.com/TykTechnologies/tykcommon"
	logger "github.com/TykTechnologies/tykcommon-logger"
	"github.com/docopt/docopt.go"
	"github.com/facebookgo/pidfile"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/lonelycode/logrus-graylog-hook"
	osin "github.com/lonelycode/osin"
	"github.com/rs/cors"
	"rsc.io/letsencrypt"
)

var log = logger.GetLogger()
var config = Config{}
var templates = &template.Template{}
var analytics = RedisAnalyticsHandler{}
var profileFile = &os.File{}
var GlobalEventsJSVM = &JSVM{}
var doMemoryProfile bool
var doCpuProfile bool
var Policies = make(map[string]Policy)
var MainNotifier = RedisNotifier{}
var DefaultOrgStore = DefaultSessionManager{}
var DefaultQuotaStore = DefaultSessionManager{}
var FallbackKeySesionManager SessionHandler = &DefaultSessionManager{}
var MonitoringHandler TykEventHandler
var RPCListener = RPCStorageHandler{}
var argumentsBackup map[string]interface{}
var DashService DashboardServiceSender

var ApiSpecRegister *map[string]*APISpec //make(map[string]*APISpec)
var keyGen = DefaultKeyGenerator{}

var mainRouter *mux.Router
var defaultRouter *mux.Router
var LE_MANAGER letsencrypt.Manager
var LE_FIRSTRUN bool

var NodeID string

// Generic system error
const (
	E_SYSTEM_ERROR          string = "{\"status\": \"system error, please contact administrator\"}"
	OAUTH_AUTH_CODE_TIMEOUT int    = 60 * 60
	OAUTH_PREFIX            string = "oauth-data."
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

	if (config.EnableAnalytics == true) && (config.Storage.Type != "redis") {
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
			thisPurger := RPCPurger{Store: &AnalyticsStore, Address: config.SlaveOptions.ConnectionString}
			thisPurger.Connect()
			analytics.Clean = &thisPurger
			go analytics.Clean.StartPurgeLoop(10)
		}

	}

	//genericOsinStorage = MakeNewOsinServer()

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
		var monitorErr error
		MonitoringHandler, monitorErr = WebHookHandler{}.New(config.Monitor.Config)
		if monitorErr != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error("Failed to initialise monitor! ", monitorErr)
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

	if config.DisableDashboardZeroConf == false && config.DBAppConfOptions.ConnectionString == "" {
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
var APILoader APIDefinitionLoader = APIDefinitionLoader{}

func getAPISpecs() *[]*APISpec {
	var APISpecs *[]*APISpec

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
	}).Printf("Detected %v APIs", len(*APISpecs))

	if config.AuthOverride.ForceAuthProvider {
		for i, _ := range *APISpecs {
			(*APISpecs)[i].AuthProvider = config.AuthOverride.AuthProvider

		}
	}

	if config.AuthOverride.ForceSessionProvider {
		for i, _ := range *APISpecs {
			(*APISpecs)[i].SessionProvider = config.AuthOverride.SessionProvider
		}
	}

	return APISpecs
}

func getPolicies() {
	thesePolicies := make(map[string]Policy)
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

			thesePolicies = LoadPoliciesFromDashboard(connStr, config.NodeSecret, config.Policies.AllowExplicitPolicyID)

		} else {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatal("No connection string or node ID present. Failing.")
		}

	} else if config.Policies.PolicySource == "rpc" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Using Policies from RPC")
		thesePolicies = LoadPoliciesFromRPC(config.SlaveOptions.RPCKey)
	} else {
		// this is the only case now where we need a policy record name
		if config.Policies.PolicyRecordName == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("No policy record name defined, skipping...")
			return
		}
		thesePolicies = LoadPoliciesFromFile(config.Policies.PolicyRecordName)
	}

	if len(thesePolicies) > 0 {
		Policies = thesePolicies
		return
	}
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(Muxer *mux.Router) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Initialising Tyk REST API Endpoints")

	var ApiMuxer *mux.Router
	ApiMuxer = Muxer
	if config.EnableAPISegregation {
		if config.ControlAPIHostname != "" {
			ApiMuxer = Muxer.Host(config.ControlAPIHostname).Subrouter()
		}
	}

	// set up main API handlers
	ApiMuxer.HandleFunc("/tyk/reload/group", CheckIsAPIOwner(groupResetHandler))
	ApiMuxer.HandleFunc("/tyk/reload/", CheckIsAPIOwner(resetHandler))

	if !IsRPCMode() {
		ApiMuxer.HandleFunc("/tyk/org/keys/"+"{rest:.*}", CheckIsAPIOwner(orgHandler))
		ApiMuxer.HandleFunc("/tyk/keys/policy/"+"{rest:.*}", CheckIsAPIOwner(policyUpdateHandler))
		ApiMuxer.HandleFunc("/tyk/keys/create", CheckIsAPIOwner(createKeyHandler))
		ApiMuxer.HandleFunc("/tyk/apis/"+"{rest:.*}", CheckIsAPIOwner(apiHandler))
		ApiMuxer.HandleFunc("/tyk/health/", CheckIsAPIOwner(healthCheckhandler))
		ApiMuxer.HandleFunc("/tyk/oauth/clients/create", CheckIsAPIOwner(createOauthClient))
		ApiMuxer.HandleFunc("/tyk/oauth/refresh/"+"{rest:.*}", CheckIsAPIOwner(invalidateOauthRefresh))
		ApiMuxer.HandleFunc("/tyk/cache/"+"{rest:.*}", CheckIsAPIOwner(invalidateCacheHandler))
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Node is slaved, REST API minimised")
	}

	ApiMuxer.HandleFunc("/tyk/keys/"+"{rest:.*}", CheckIsAPIOwner(keyHandler))
	ApiMuxer.HandleFunc("/tyk/oauth/clients/"+"{rest:.*}", CheckIsAPIOwner(oAuthClientHandler))

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("Loaded API Endpoints")
}

func generateOAuthPrefix(apiID string) string {
	return OAUTH_PREFIX + apiID + "."
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

	OAuthPrefix := generateOAuthPrefix(spec.APIID)
	//storageManager := RedisClusterStorageManager{KeyPrefix: OAuthPrefix}
	storageManager := GetGlobalStorageHandler(OAuthPrefix, false)
	storageManager.Connect()
	osinStorage := RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

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

	// osinServer.AccessTokenGen = &AccessTokenGenTyk{}

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
	thisBatchHandler := BatchRequestHandler{API: spec}
	Muxer.HandleFunc(apiBatchPath, thisBatchHandler.HandleBatchRequest)
}

func loadCustomMiddleware(referenceSpec *APISpec) ([]string, tykcommon.MiddlewareDefinition, []tykcommon.MiddlewareDefinition, []tykcommon.MiddlewareDefinition, []tykcommon.MiddlewareDefinition, tykcommon.MiddlewareDriver) {
	mwPaths := []string{}
	var mwAuthCheckFunc tykcommon.MiddlewareDefinition
	mwPreFuncs := []tykcommon.MiddlewareDefinition{}
	mwPostFuncs := []tykcommon.MiddlewareDefinition{}
	mwPostKeyAuthFuncs := []tykcommon.MiddlewareDefinition{}
	mwDriver := tykcommon.OttoDriver

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

	// Load from folder

	// Get PRE folder path
	middlwareFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "pre")
	files, _ := ioutil.ReadDir(middlwareFolderPath)
	for _, f := range files {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlwareFolderPath, f.Name())
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Loading PRE-PROCESSOR file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware name ", middlewareObjectName)

			requiresSession := strings.Contains(middlewareObjectName, "_with_session")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware requires session: ", requiresSession)
			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = requiresSession

			mwPaths = append(mwPaths, filePath)
			mwPreFuncs = append(mwPreFuncs, thisMWDef)
		}
	}

	// Get Auth folder path
	middlewareAuthFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "auth")
	mwAuthFiles, _ := ioutil.ReadDir(middlewareAuthFolderPath)
	for _, f := range mwAuthFiles {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlewareAuthFolderPath, f.Name())
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Loading Auth file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware name ", middlewareObjectName)

			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = false

			mwPaths = append(mwPaths, filePath)
			mwAuthCheckFunc = thisMWDef
			// only one allowed!
			break
		}
	}

	// Get POSTKeyAuth folder path
	middlewarePostKeyAuthFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "post_auth")
	mwPostKeyAuthFiles, _ := ioutil.ReadDir(middlewarePostKeyAuthFolderPath)
	for _, f := range mwPostKeyAuthFiles {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlewarePostKeyAuthFolderPath, f.Name())
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Loading POST-KEY-AUTH-PROCESSOR file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware name ", middlewareObjectName)

			requiresSession := strings.Contains(middlewareObjectName, "_with_session")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware requires session: ", requiresSession)
			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = requiresSession

			mwPaths = append(mwPaths, filePath)
			mwPostKeyAuthFuncs = append(mwPostFuncs, thisMWDef)
		}
	}

	// Get POST folder path
	middlewarePostFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "post")
	mwPostFiles, _ := ioutil.ReadDir(middlewarePostFolderPath)
	for _, f := range mwPostFiles {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlewarePostFolderPath, f.Name())
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("Loading POST-PROCESSOR file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware name ", middlewareObjectName)

			requiresSession := strings.Contains(middlewareObjectName, "_with_session")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Debug("-- Middleware requires session: ", requiresSession)
			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = requiresSession

			mwPaths = append(mwPaths, filePath)
			mwPostFuncs = append(mwPostFuncs, thisMWDef)
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
		thisProcessor, _ := processorType.New(processorDetail.Options, referenceSpec)
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = thisProcessor
	}
	referenceSpec.ResponseChain = &responseChain
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
	if config.AuthOverride.ForceAuthProvider {
		if config.AuthOverride.AuthProvider.StorageEngine == RPCStorageEngine {
			return true
		}
	}
	return false
}

func doCopy(from *APISpec, to *APISpec) {
	*to = *from
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

func RPCReloadLoop(RPCKey string) {
	for {
		RPCListener.CheckForReload(config.SlaveOptions.RPCKey)
	}
}

func doReload() {
	time.Sleep(10 * time.Second)

	// Load the API Policies
	getPolicies()

	// load the specs
	specs := getAPISpecs()

	if len(*specs) == 0 {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("No API Definitions found, not reloading")
		reloadScheduled = false
		return
	}

	// We have updated specs, lets load those...

	// Kill RPC if available
	if config.SlaveOptions.UseRPC {
		ClearRPCClients()
	}

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

	loadAPIEndpoints(newMuxes)
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

	reloadScheduled = false
}

var reloadScheduled bool

func checkReloadTimeout() {
	if reloadScheduled {
		wait := config.ReloadWaitTime
		if config.ReloadWaitTime == 0 {
			wait = 10
		}
		time.Sleep(time.Duration(wait) * time.Second)
		if reloadScheduled {
			log.Warning("Reloader timed out! Removing sentinel")
			reloadScheduled = false
		}
	}
}

// ReloadURLStructure will create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one, this enables a
// reconfiguration to take place without stopping any requests from being handled.
func ReloadURLStructure() {
	if !reloadScheduled {
		reloadScheduled = true
		log.Info("Initiating reload")
		go doReload()
		log.Info("Initiating coprocess reload")
		go doCoprocessReload()
		log.Info("Starting reload monitor...")
		go checkReloadTimeout()
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
	for k, _ := range CommandModeOptions {

		v := arguments[k]

		if v == true {
			HandleCommandModeArgs(arguments)
			os.Exit(0)
		}

		if v != nil && v != false {
			HandleCommandModeArgs(arguments)
			os.Exit(0)
		}

	}

	filename := "/etc/tyk/tyk.conf"
	value, _ := arguments["--conf"]
	if value != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug(fmt.Sprintf("Using %s for configuration", value.(string)))
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
			}).Error("Port specified in flags must be a number!")
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Error(err)
		} else {
			config.ListenPort = portNum
		}
	}

	doMemoryProfile, _ = arguments["--memprofile"].(bool)
	doCpuProfile, _ = arguments["--cpuprofile"].(bool)

	doDebug, _ := arguments["--debug"]
	log.Level = logrus.InfoLevel
	if doDebug == true {
		log.Level = logrus.DebugLevel
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Debug("Enabling debug-level output")
	}

	// Enable all the loggers
	setupLogger()

	if config.PIDFileLocation == "" {
		config.PIDFileLocation = "/var/run/tyk-gateway.pid"
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("PIDFile location set to: ", config.PIDFileLocation)

	pidfile.SetPidfilePath(config.PIDFileLocation)
	pfErr := pidfile.Write()

	if pfErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("Failed to write PIDFile: ", pfErr)
	}

	GetHostDetails()

	go StartPeriodicStateBackup(&LE_MANAGER)
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
		--debug                      Enable Debug output
		--import-blueprint=<file>    Import an API Blueprint file
		--import-swagger=<file>      Import a Swagger file
		--create-api                 Creates a new API Definition from the blueprint
		--org-id=><id>               Assign the API Defintition to this org_id (required with create)
		--upstream-target=<url>      Set the upstream target for the definition
		--as-mock                    Creates the API as a mock based on example fields
		--for-api=<path>             Adds blueprint to existing API Defintition as version
		--as-version=<version>       The version number to use when inserting
	`

	arguments, err := docopt.Parse(usage, nil, true, VERSION, false, false)
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
			if engine.Killed == true {
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
	var Name tykcommon.StorageEngineCode
	// Select configuration options
	if config.SlaveOptions.UseRPC {
		Name = RPCStorageEngine
	} else {
		Name = DefaultStorageEngine
	}

	switch Name {
	case DefaultStorageEngine:
		return &RedisClusterStorageManager{KeyPrefix: KeyPrefix, HashKeys: hashKeys}
	case RPCStorageEngine:
		engine := &RPCStorageHandler{KeyPrefix: KeyPrefix, HashKeys: hashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
		return engine
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Error("No storage handler found!")
	return nil
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

	if nil != goAgainErr {
		initialiseSystem(arguments)
		start()

		var listenerErr error
		l, listenerErr = generateListener(l)

		// Check if listener was started successfully.
		if listenerErr != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Fatalf("Error starting listener: %s", listenerErr)
		}

		listen(l, goAgainErr)
	} else {
		initialiseSystem(arguments)
		start()

		listen(l, goAgainErr)

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
		profileFile, _ = os.Create("tyk.mprof")
		defer profileFile.Close()
	}
	if doCpuProfile {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Cpu profiling active")
		profileFile, _ = os.Create("tyk.prof")
		pprof.StartCPUProfile(profileFile)
		defer pprof.StopCPUProfile()
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

	loadAPIEndpoints(defaultRouter)

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

func generateListener(l net.Listener) (net.Listener, error) {
	targetPort := fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort)

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
		err := DashService.Register()
		if err != nil {
			log.Fatal("Registration failed: ", err)
		}

		startHeartBeat()
	}
}

func startHeartBeat() {
	// heartbeatConnStr := config.DBAppConfOptions.ConnectionString
	// if heartbeatConnStr == "" && config.DisableDashboardZeroConf {
	// 	log.Fatal("Connection string is empty, failing.")
	// }

	// log.WithFields(logrus.Fields{
	// 	"prefix": "main",
	// }).Info("Starting heartbeat.")
	// heartbeatConnStr = heartbeatConnStr + "/register/ping"
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

func listen(l net.Listener, err error) {
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
			loadApps(specs, defaultRouter)
			getPolicies()
		}

		// Use a custom server so we can control keepalives
		if config.HttpServerOptions.OverrideDefaults {
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
			displayConfig()
		}

	} else {

		// handle dashboard registration and nonces if available
		thisNonce := os.Getenv("TYK_SERVICE_NONCE")
		thisID := os.Getenv("TYK_SERVICE_NODEID")
		if thisNonce == "" || thisID == "" {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Warning("No nonce found, re-registering")
			handleDashboardRegistration()

		} else {
			NodeID = thisID
			ServiceNonce = thisNonce
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
			loadApps(specs, defaultRouter)
			getPolicies()
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
