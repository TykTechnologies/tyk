package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/Sirupsen/logrus/hooks/sentry"
	"github.com/docopt/docopt.go"
	"github.com/justinas/alice"
	osin "github.com/lonelycode/osin"
	"github.com/lonelycode/tykcommon"
	"github.com/rcrowley/goagain"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var log = logrus.New()
var config = Config{}
var templates = &template.Template{}
var analytics = RedisAnalyticsHandler{}
var profileFile = &os.File{}
var GlobalEventsJSVM = &JSVM{}
var doMemoryProfile bool
var Policies = make(map[string]Policy)
var MainNotifier = RedisNotifier{}
var DefaultOrgStore = DefaultSessionManager{}
var DefaultQuotaStore = DefaultSessionManager{}
var MonitoringHandler TykEventHandler

//var genericOsinStorage *RedisOsinStorageInterface
var ApiSpecRegister = make(map[string]*APISpec)
var keyGen = DefaultKeyGenerator{}

// Generic system error
const (
	E_SYSTEM_ERROR          string = "{\"status\": \"system error, please contact administrator\"}"
	OAUTH_AUTH_CODE_TIMEOUT int    = 60 * 60
	OAUTH_PREFIX            string = "oauth-data."
)

// Display configuration options
func displayConfig() {
	log.Info("Listening on port: ", config.ListenPort)
}

// Create all globals and init connection handlers
func setupGlobals() {

	if (config.EnableAnalytics == true) && (config.Storage.Type != "redis") {
		log.Panic("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	if config.EnableAnalytics {
		config.loadIgnoredIPs()
		AnalyticsStore := RedisStorageManager{KeyPrefix: "analytics-"}
		log.Info("Setting up analytics DB connection")

		analytics = RedisAnalyticsHandler{
			Store: &AnalyticsStore,
		}

		if config.AnalyticsConfig.Type == "csv" {
			log.Info("Using CSV cache purge")
			analytics.Clean = &CSVPurger{&AnalyticsStore}

		} else if config.AnalyticsConfig.Type == "mongo" {
			log.Info("Using MongoDB cache purge")
			analytics.Clean = &MongoPurger{&AnalyticsStore, nil}
		} else if config.AnalyticsConfig.Type == "rpc" {
			log.Info("Using RPC cache purge")
			thisPurger := RPCPurger{Store: &AnalyticsStore, Address: config.SlaveOptions.ConnectionString}
			thisPurger.Connect()
			analytics.Clean = &thisPurger
		}

		analytics.Store.Connect()

		if config.AnalyticsConfig.PurgeDelay >= 0 {
			go analytics.Clean.StartPurgeLoop(config.AnalyticsConfig.PurgeDelay)
		} else {
			log.Warn("Cache purge turned off, you are responsible for Redis storage maintenance.")
		}
	}

	//genericOsinStorage = MakeNewOsinServer()

	templateFile := fmt.Sprintf("%s/error.json", config.TemplatePath)
	templates = template.Must(template.ParseFiles(templateFile))

	// Set up global JSVM
	GlobalEventsJSVM.Init(config.TykJSPath)

	// Get the notifier ready
	log.Warning("Notifier will not work in hybrid mode")
	MainNotifierStore := RedisStorageManager{}
	MainNotifierStore.Connect()
	MainNotifier = RedisNotifier{&MainNotifierStore, RedisPubSubChannel}

	if config.Monitor.EnableTriggerMonitors {
		var monitorErr error
		MonitoringHandler, monitorErr = WebHookHandler{}.New(config.Monitor.Config)
		if monitorErr != nil {
			log.Error("Failed to initialise monitor! ", monitorErr)
		}
	}
}

// Pull API Specs from configuration
func getAPISpecs() []APISpec {
	var APISpecs []APISpec
	thisAPILoader := APIDefinitionLoader{}

	if config.UseDBAppConfigs {
		log.Info("Using App Configuration from Mongo DB")
		APISpecs = thisAPILoader.LoadDefinitionsFromMongo()
	} else if config.SlaveOptions.UseRPC {
		log.Info("Using RPC Configuration")
		APISpecs = thisAPILoader.LoadDefinitionsFromRPC(config.SlaveOptions.RPCKey)
	} else {
		APISpecs = thisAPILoader.LoadDefinitions(config.AppPath)
	}

	return APISpecs
}

func getPolicies() {
	log.Info("Loading policies")
	if config.Policies.PolicyRecordName == "" {
		log.Info("No policy record name defined, skipping...")
		return
	}

	if config.Policies.PolicySource == "mongo" {
		log.Info("Using Policies from Mongo DB")
		Policies = LoadPoliciesFromMongo(config.Policies.PolicyRecordName)
	} else if config.Policies.PolicySource == "rpc" {
		log.Info("Using Policies from RPC")
		Policies = LoadPoliciesFromRPC(config.SlaveOptions.RPCKey)
	} else {
		Policies = LoadPoliciesFromFile(config.Policies.PolicyRecordName)
	}
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(Muxer *http.ServeMux) {
	// set up main API handlers
	Muxer.HandleFunc("/tyk/org/keys/", CheckIsAPIOwner(orgHandler))
	Muxer.HandleFunc("/tyk/keys/create", CheckIsAPIOwner(createKeyHandler))
	Muxer.HandleFunc("/tyk/keys/", CheckIsAPIOwner(keyHandler))
	Muxer.HandleFunc("/tyk/apis/", CheckIsAPIOwner(apiHandler))
	Muxer.HandleFunc("/tyk/health/", CheckIsAPIOwner(healthCheckhandler))
	Muxer.HandleFunc("/tyk/reload/group", CheckIsAPIOwner(groupResetHandler))
	Muxer.HandleFunc("/tyk/reload/", CheckIsAPIOwner(resetHandler))
	Muxer.HandleFunc("/tyk/oauth/clients/create", CheckIsAPIOwner(createOauthClient))
	Muxer.HandleFunc("/tyk/oauth/clients/", CheckIsAPIOwner(oAuthClientHandler))
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec *APISpec, Muxer *http.ServeMux, test bool) *OAuthManager {
	apiAuthorizePath := spec.Proxy.ListenPath + "tyk/oauth/authorize-client/"
	clientAuthPath := spec.Proxy.ListenPath + "oauth/authorize/"
	clientAccessPath := spec.Proxy.ListenPath + "oauth/token/"

	serverConfig := osin.NewServerConfig()
	serverConfig.ErrorStatusCode = 403
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes

	OAuthPrefix := OAUTH_PREFIX + spec.APIID + "."
	//storageManager := RedisStorageManager{KeyPrefix: OAuthPrefix}
	storageManager := GetGlobalStorageHandler(OAuthPrefix, false)
	storageManager.Connect()
	osinStorage := RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	if test {
		log.Warning("Adding test client")
		testClient := osin.DefaultClient{
			Id:          "1234",
			Secret:      "aabbccdd",
			RedirectUri: "http://client.oauth.com",
		}
		osinStorage.SetClient(testClient.Id, &testClient, false)
		log.Warning("Test client added")
	}

	osinServer := TykOsinNewServer(serverConfig, osinStorage)
	osinServer.AccessTokenGen = &AccessTokenGenTyk{}

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	Muxer.HandleFunc(apiAuthorizePath, CheckIsAPIOwner(oauthHandlers.HandleGenerateAuthCodeData))
	Muxer.HandleFunc(clientAuthPath, oauthHandlers.HandleAuthorizePassthrough)
	Muxer.HandleFunc(clientAccessPath, oauthHandlers.HandleAccessRequest)

	return &oauthManager
}

func addBatchEndpoint(spec *APISpec, Muxer *http.ServeMux) {
	log.Info("Batch requests enabled for API")
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	thisBatchHandler := BatchRequestHandler{API: spec}
	Muxer.HandleFunc(apiBatchPath, thisBatchHandler.HandleBatchRequest)
}

func loadCustomMiddleware(referenceSpec *APISpec) ([]string, []tykcommon.MiddlewareDefinition, []tykcommon.MiddlewareDefinition) {
	mwPaths := []string{}
	mwPreFuncs := []tykcommon.MiddlewareDefinition{}
	mwPostFuncs := []tykcommon.MiddlewareDefinition{}

	// Load form the configuration
	for _, mwObj := range referenceSpec.APIDefinition.CustomMiddleware.Pre {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPreFuncs = append(mwPreFuncs, mwObj)
		log.Info("Loading custom PRE-PROCESSOR middleware: ", mwObj.Name)
	}
	for _, mwObj := range referenceSpec.APIDefinition.CustomMiddleware.Post {
		mwPaths = append(mwPaths, mwObj.Path)
		mwPostFuncs = append(mwPostFuncs, mwObj)
		log.Info("Loading custom POST-PROCESSOR middleware: ", mwObj.Name)
	}

	// Load from folder

	// Get PRE folder path
	middlwareFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "pre")
	files, _ := ioutil.ReadDir(middlwareFolderPath)
	for _, f := range files {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlwareFolderPath, f.Name())
			log.Info("Loading PRE-PROCESSOR file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.Info("-- Middleware name ", middlewareObjectName)

			requiresSession := strings.Contains(middlewareObjectName, "_with_session")
			log.Info("-- Middleware requires session: ", requiresSession)
			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = requiresSession

			mwPaths = append(mwPaths, filePath)
			mwPreFuncs = append(mwPostFuncs, thisMWDef)
		}
	}

	// Get POST folder path
	middlewarePostFolderPath := path.Join(config.MiddlewarePath, referenceSpec.APIDefinition.APIID, "post")
	mwPostFiles, _ := ioutil.ReadDir(middlewarePostFolderPath)
	for _, f := range mwPostFiles {
		if strings.Contains(f.Name(), ".js") {
			filePath := filepath.Join(middlewarePostFolderPath, f.Name())
			log.Info("Loading POST-PROCESSOR file middleware from ", filePath)
			middlewareObjectName := strings.Split(f.Name(), ".")[0]
			log.Info("-- Middleware name ", middlewareObjectName)

			requiresSession := strings.Contains(middlewareObjectName, "_with_session")
			log.Info("-- Middleware requires session: ", requiresSession)
			thisMWDef := tykcommon.MiddlewareDefinition{}
			thisMWDef.Name = middlewareObjectName
			thisMWDef.Path = filePath
			thisMWDef.RequireSession = requiresSession

			mwPaths = append(mwPaths, filePath)
			mwPreFuncs = append(mwPreFuncs, thisMWDef)
		}
	}

	return mwPaths, mwPreFuncs, mwPostFuncs

}

func creeateResponseMiddlewareChain(referenceSpec *APISpec) {
	// Create the response processors

	responseChain := make([]TykResponseHandler, len(referenceSpec.APIDefinition.ResponseProcessors))
	for i, processorDetail := range referenceSpec.APIDefinition.ResponseProcessors {
		processorType, err := GetResponseProcessorByName(processorDetail.Name)
		if err != nil {
			log.Error("Failed to load processor! ", err)
			return
		}
		thisProcessor, _ := processorType.New(processorDetail.Options, referenceSpec)
		log.Info("Loading Response processor: ", processorDetail.Name)
		responseChain[i] = thisProcessor
	}
	referenceSpec.ResponseChain = &responseChain
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(APISpecs []APISpec, Muxer *http.ServeMux) {
	// load the APi defs
	log.Info("Loading API configurations.")

	// Only create this once, add other types here as needed, seems wasteful but we can let the GC handle it
	redisStore := RedisStorageManager{KeyPrefix: "apikey-", HashKeys: config.HashKeys}
	redisOrgStore := RedisStorageManager{KeyPrefix: "orgkey."}

	// Create a new handler for each API spec
	for apiIndex, _ := range APISpecs {
		// We need a reference to this as we change it on the go and re-use it in a global index
		referenceSpec := APISpecs[apiIndex]
		log.Info("Loading API Spec for: ", referenceSpec.APIDefinition.Name)

		remote, err := url.Parse(referenceSpec.APIDefinition.Proxy.TargetURL)
		if err != nil {
			log.Error("Culdn't parse target URL")
			log.Error(err)
		}

		// Initialise the auth and session managers (use Redis for now)
		var authStore StorageHandler
		var sessionStore StorageHandler
		var orgStore StorageHandler

		authStorageEngineToUse := referenceSpec.AuthProvider.StorageEngine
		if config.SlaveOptions.OverrideDefinitionStorageSettings {
			authStorageEngineToUse = RPCStorageEngine
		}

		switch authStorageEngineToUse {
		case DefaultStorageEngine:
			authStore = &redisStore
		case LDAPStorageEngine:
			thisStorageEngine := LDAPStorageHandler{}
			thisStorageEngine.LoadConfFromMeta(referenceSpec.AuthProvider.Meta)
			authStore = &thisStorageEngine
		case RPCStorageEngine:
			thisStorageEngine := &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.HashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
			authStore = thisStorageEngine
		default:
			authStore = &redisStore
		}

		SessionStorageEngineToUse := referenceSpec.SessionProvider.StorageEngine
		if config.SlaveOptions.OverrideDefinitionStorageSettings {
			SessionStorageEngineToUse = RPCStorageEngine
		}

		switch SessionStorageEngineToUse {
		case DefaultStorageEngine:
			sessionStore = &redisStore
			orgStore = &redisOrgStore
		case RPCStorageEngine:
			sessionStore = &RPCStorageHandler{KeyPrefix: "apikey-", HashKeys: config.HashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
			orgStore = &RPCStorageHandler{KeyPrefix: "orgkey.", UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
		default:
			sessionStore = &redisStore
			orgStore = &redisOrgStore
		}

		// Health checkers are initialised per spec so that each API handler has it's own connection and redis sotorage pool
		healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}
		referenceSpec.Init(authStore, sessionStore, healthStore, orgStore)

		//Set up all the JSVM middleware
		mwPaths := []string{}
		mwPreFuncs := []tykcommon.MiddlewareDefinition{}
		mwPostFuncs := []tykcommon.MiddlewareDefinition{}

		log.Info("Loading Middleware")
		mwPaths, mwPreFuncs, mwPostFuncs = loadCustomMiddleware(&referenceSpec)

		referenceSpec.JSVM.LoadJSPaths(mwPaths)

		if referenceSpec.EnableBatchRequestSupport {
			addBatchEndpoint(&referenceSpec, Muxer)
		}

		if referenceSpec.UseOauth2 {
			thisOauthManager := addOAuthHandlers(&referenceSpec, Muxer, false)
			referenceSpec.OAuthManager = thisOauthManager
		}

		proxy := TykNewSingleHostReverseProxy(remote, &referenceSpec)
		referenceSpec.target = remote

		// Create the response processors
		creeateResponseMiddlewareChain(&referenceSpec)

		//proxyHandler := http.HandlerFunc(ProxyHandler(proxy, referenceSpec))
		tykMiddleware := &TykMiddleware{&referenceSpec, proxy}

		keyPrefix := "cache-" + referenceSpec.APIDefinition.APIID
		CacheStore := &RedisStorageManager{KeyPrefix: keyPrefix}
		CacheStore.Connect()

		if referenceSpec.APIDefinition.UseKeylessAccess {
			// for KeyLessAccess we can't support rate limiting, versioning or access rules
			chain := alice.New(CreateMiddleware(&IPWhiteListMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&TransformMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&TransformHeaders{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&RedisCacheMiddleware{TykMiddleware: tykMiddleware, CacheStore: CacheStore}, tykMiddleware)).Then(DummyProxyHandler{SH: SuccessHandler{tykMiddleware}})
			Muxer.Handle(referenceSpec.Proxy.ListenPath, chain)

		} else {

			// Select the keying method to use for setting session states
			var keyCheck func(http.Handler) http.Handler

			if referenceSpec.APIDefinition.UseOauth2 {
				// Oauth2
				keyCheck = CreateMiddleware(&Oauth2KeyExists{tykMiddleware}, tykMiddleware)
			} else if referenceSpec.APIDefinition.UseBasicAuth {
				// Basic Auth
				keyCheck = CreateMiddleware(&BasicAuthKeyIsValid{tykMiddleware}, tykMiddleware)
			} else if referenceSpec.EnableSignatureChecking {
				// HMAC Auth
				keyCheck = CreateMiddleware(&HMACMiddleware{tykMiddleware}, tykMiddleware)
			} else {
				// Auth key
				keyCheck = CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware)
			}

			var chainArray = []alice.Constructor{}

			var baseChainArray = []alice.Constructor{
				CreateMiddleware(&IPWhiteListMiddleware{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
				keyCheck,
				CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&GranularAccessMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&TransformMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&TransformHeaders{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&RedisCacheMiddleware{TykMiddleware: tykMiddleware, CacheStore: CacheStore}, tykMiddleware),
			}

			// Add pre-process MW
			for _, obj := range mwPreFuncs {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, true, obj.RequireSession, tykMiddleware))
			}

			for _, baseMw := range baseChainArray {
				chainArray = append(chainArray, baseMw)
			}

			for _, obj := range mwPostFuncs {
				chainArray = append(chainArray, CreateDynamicMiddleware(obj.Name, false, obj.RequireSession, tykMiddleware))
			}

			// Use CreateMiddleware(&ModifiedMiddleware{tykMiddleware}, tykMiddleware)  to run custom middleware
			chain := alice.New(chainArray...).Then(DummyProxyHandler{SH: SuccessHandler{tykMiddleware}})

			userCheckHandler := http.HandlerFunc(UserRatesCheck())
			simpleChain := alice.New(
				CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&OrganizationMonitor{TykMiddleware: tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{TykMiddleware: tykMiddleware}, tykMiddleware),
				keyCheck,
				CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware)).Then(userCheckHandler)

			rateLimitPath := fmt.Sprintf("%s%s", referenceSpec.Proxy.ListenPath, "tyk/rate-limits/")
			log.Info("Rate limits available at: ", rateLimitPath)
			Muxer.Handle(rateLimitPath, simpleChain)
			Muxer.Handle(referenceSpec.Proxy.ListenPath, chain)
		}

		ApiSpecRegister[referenceSpec.APIDefinition.APIID] = &referenceSpec

	}

}

// ReloadURLStructure will create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one, this enables a
// reconfiguration to take place without stopping any requests from being handled.
func ReloadURLStructure() {
	// Kill RPC if available
	if config.SlaveOptions.UseRPC {
		ClearRPCClients()
	}

	// Reset the JSVM
	GlobalEventsJSVM.Init(config.TykJSPath)

	newMuxes := http.NewServeMux()
	loadAPIEndpoints(newMuxes)
	specs := getAPISpecs()
	loadApps(specs, newMuxes)

	// Load the API Policies
	getPolicies()

	http.DefaultServeMux = newMuxes
	log.Info("Reload complete")
}

func init() {

	usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help                    Show this screen
		--conf=FILE                  Load a named configuration file
		--port=PORT                  Listen on PORT (overrides confg file)
		--memprofile                 Generate a memory profile
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

	arguments, err := docopt.Parse(usage, nil, true, "v1.7.2", false, false)
	if err != nil {
		log.Warning("Error while parsing arguments: ", err)
	}

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
		log.Info(fmt.Sprintf("Using %s for configuration", value.(string)))
		filename = arguments["--conf"].(string)
	} else {
		log.Info("No configuration file defined, will try to use default (./tyk.conf)")
	}

	loadConfig(filename, &config)

	if config.Storage.Type != "redis" {
		log.Fatal("Redis connection details not set, please ensure that the storage type is set to Redis and that the connection parameters are correct.")
	}

	setupGlobals()

	port, _ := arguments["--port"]
	if port != nil {
		portNum, err := strconv.Atoi(port.(string))
		if err != nil {
			log.Error("Port specified in flags must be a number!")
			log.Error(err)
		} else {
			config.ListenPort = portNum
		}
	}

	doMemoryProfile, _ = arguments["--memprofile"].(bool)

	doDebug, _ := arguments["--debug"]
	log.Level = logrus.InfoLevel
	if doDebug == true {
		log.Level = logrus.DebugLevel
		log.Debug("Enabling debug-level output")
	}

	if config.UseSentry {
		log.Info("Enabling Sentry support")
		hook, err := logrus_sentry.NewSentryHook(config.SentryCode, []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		})

		hook.Timeout = 0

		if err == nil {
			log.Hooks.Add(hook)
		}
		log.Info("Sentry hook active")
	}

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
		return &RedisStorageManager{KeyPrefix: KeyPrefix, HashKeys: hashKeys}
	case RPCStorageEngine:
		return &RPCStorageHandler{KeyPrefix: KeyPrefix, HashKeys: hashKeys, UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	}

	log.Error("No storage handler found!")
	return nil
}

func main() {
	displayConfig()

	ReadTimeout := 120
	WriteTimeout := 120
	if config.HttpServerOptions.ReadTimeout > 0 {
		ReadTimeout = config.HttpServerOptions.ReadTimeout
	}

	if config.HttpServerOptions.WriteTimeout > 0 {
		WriteTimeout = config.HttpServerOptions.WriteTimeout
	}

	if doMemoryProfile {
		log.Info("Memory profiling active")
		profileFile, _ = os.Create("tyk.mprof")
		defer profileFile.Close()
	}

	targetPort := fmt.Sprintf(":%d", config.ListenPort)

	// Set up a default org manager so we can traverse non-live paths
	if !config.SupressDefaultOrgStore {
		log.Info("Initialising default org store")
		//DefaultOrgStore.Init(&RedisStorageManager{KeyPrefix: "orgkey."})
		DefaultOrgStore.Init(GetGlobalStorageHandler("orgkey.", false))
		//DefaultQuotaStore.Init(GetGlobalStorageHandler(CloudHandler, "orgkey.", false))
		DefaultQuotaStore.Init(GetGlobalStorageHandler("orgkey.", false))
	}

	loadAPIEndpoints(http.DefaultServeMux)

	// Start listening for reload messages
	if !config.SuppressRedisSignalReload {
		go StartPubSubLoop()
	}

	if config.SlaveOptions.UseRPC {
		log.Warning("Strting RPC reload listener!")
		RPCListener := RPCStorageHandler{KeyPrefix: "rpc.listener.", UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
		RPCListener.Connect()
		go RPCListener.CheckForReload(config.SlaveOptions.RPCKey)
	}

	// Handle reload when SIGUSR2 is received
	l, err := goagain.Listener()
	if nil != err {

		// Listen on a TCP or a UNIX domain socket (TCP here).
		l, err = net.Listen("tcp", targetPort)
		if nil != err {
			log.Fatalln(err)
		}
		log.Println("Listening on", l.Addr())

		// Accept connections in a new goroutine.
		specs := getAPISpecs()
		loadApps(specs, http.DefaultServeMux)
		getPolicies()

		// Use a custom server so we can control keepalives
		log.Warning("YES? ", config.HttpServerOptions.OverrideDefaults)
		if config.HttpServerOptions.OverrideDefaults {
			log.Info("Server started.")
			log.Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(WriteTimeout) * time.Second,
				Handler:      http.DefaultServeMux,
			}

			go s.Serve(l)
		} else {
			log.Info("Server started.")
			go http.Serve(l, nil)
		}

	} else {

		// Resume accepting connections in a new goroutine.
		log.Println("Resuming listening on", l.Addr())
		specs := getAPISpecs()
		loadApps(specs, http.DefaultServeMux)
		getPolicies()

		if config.HttpServerOptions.OverrideDefaults {
			log.Warning("HTTP Server Overrides detected, this could destabilise long-running http-requests")
			s := &http.Server{
				Addr:         ":" + targetPort,
				ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(WriteTimeout) * time.Second,
				Handler:      http.DefaultServeMux,
			}

			log.Info("Server started.")
			go s.Serve(l)
		} else {
			log.Info("Server started.")
			http.Serve(l, nil)
		}

		// Kill the parent, now that the child has started successfully.
		if err := goagain.Kill(); nil != err {
			log.Fatalln(err)
		}

	}

	// Block the main goroutine awaiting signals.
	if _, err := goagain.Wait(l); nil != err {
		log.Fatalln(err)
	}

	// Do whatever's necessary to ensure a graceful exit like waiting for
	// goroutines to terminate or a channel to become closed.
	//
	// In this case, we'll simply stop listening and wait one second.
	if err := l.Close(); nil != err {
		log.Fatalln(err)
	}
	time.Sleep(1e9)
}
