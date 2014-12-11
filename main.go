package main

import (
	"fmt"
	"github.com/RangelReale/osin"
	"github.com/Sirupsen/logrus"
	"github.com/buger/goterm"
	"github.com/docopt/docopt.go"
	"github.com/justinas/alice"
	"github.com/rcrowley/goagain"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var log = logrus.New()
var config = Config{}
var templates = &template.Template{}
var analytics = RedisAnalyticsHandler{}
var profileFile = &os.File{}
var doMemoryProfile bool
//var genericOsinStorage *RedisOsinStorageInterface
var ApiSpecRegister = make(map[string]*APISpec)
var keyGen = DefaultKeyGenerator{}
// Generic system error
const (
	E_SYSTEM_ERROR          string = "{\"status\": \"system error, please contact administrator\"}"
	OAUTH_AUTH_CODE_TIMEOUT int    = 60 * 60
	OAUTH_PREFIX            string = "oauth-data."
)

// Display introductory details
func intro() {
	fmt.Print("\n\n")
	fmt.Println(goterm.Bold(goterm.Color("Tyk.io Gateway API v1.2.1", goterm.GREEN)))
	fmt.Println(goterm.Bold(goterm.Color("=========================", goterm.GREEN)))
	fmt.Print("Copyright Jively Ltd. 2014")
	fmt.Print("\nhttp://www.tyk.io\n\n")
}

// Display configuration options
func displayConfig() {
	configTable := goterm.NewTable(0, 10, 5, ' ', 0)
	fmt.Fprintf(configTable, "Listening on port:\t%d\n", config.ListenPort)

	fmt.Println(configTable)
	fmt.Println("")
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
}

// Pull API Specs from configuration
func getAPISpecs() []APISpec {
	var APISpecs []APISpec
	thisAPILoader := APIDefinitionLoader{}

	if config.UseDBAppConfigs {
		log.Info("Using App Configuration from Mongo DB")
		APISpecs = thisAPILoader.LoadDefinitionsFromMongo()
	} else {
		APISpecs = thisAPILoader.LoadDefinitions(config.AppPath)
	}

	return APISpecs
}

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(Muxer *http.ServeMux) {
	// set up main API handlers
	Muxer.HandleFunc("/tyk/keys/create", CheckIsAPIOwner(createKeyHandler))
	Muxer.HandleFunc("/tyk/keys/", CheckIsAPIOwner(keyHandler))
	Muxer.HandleFunc("/tyk/apis/", CheckIsAPIOwner(apiHandler))
	Muxer.HandleFunc("/tyk/health/", CheckIsAPIOwner(healthCheckhandler))
	Muxer.HandleFunc("/tyk/reload/", CheckIsAPIOwner(resetHandler))
	Muxer.HandleFunc("/tyk/oauth/clients/create", CheckIsAPIOwner(createOauthClient))
	Muxer.HandleFunc("/tyk/oauth/clients/", CheckIsAPIOwner(oAuthClientHandler))
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec *APISpec, Muxer *http.ServeMux, test bool) *OAuthManager{
	apiAuthorizePath := spec.Proxy.ListenPath + "tyk/oauth/authorize-client/"
	clientAuthPath := spec.Proxy.ListenPath + "oauth/authorize/"
	clientAccessPath := spec.Proxy.ListenPath + "oauth/token/"

	serverConfig := osin.NewServerConfig()
	serverConfig.ErrorStatusCode = 403
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes

	OAuthPrefix := OAUTH_PREFIX + spec.APIID + "."
	storageManager := RedisStorageManager{KeyPrefix: OAuthPrefix}
	storageManager.Connect()
	osinStorage := RedisOsinStorageInterface{&storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

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
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	thisBatchHandler := BatchRequestHandler{API: spec}
	Muxer.HandleFunc(apiBatchPath, thisBatchHandler.HandleBatchRequest)
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(APISpecs []APISpec, Muxer *http.ServeMux) {
	// load the APi defs
	log.Info("Loading API configurations.")

	// Only create this once, add other types here as needed, seems wasteful but we can let the GC handle it
	redisStore := RedisStorageManager{KeyPrefix: "apikey-"}

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

		switch referenceSpec.AuthProvider.StorageEngine {
			case DefaultStorageEngine: authStore = &redisStore
			default: authStore = &redisStore
		}

		switch referenceSpec.SessionProvider.StorageEngine {
		case DefaultStorageEngine: sessionStore = &redisStore
		default: sessionStore = &redisStore
		}

		healthStore := &RedisStorageManager{KeyPrefix: "apihealth."}

		referenceSpec.Init(authStore, sessionStore, healthStore)

		if referenceSpec.EnableBatchRequestSupport {
			addBatchEndpoint(&referenceSpec, Muxer)
		}

		if referenceSpec.UseOauth2 {
			thisOauthManager := addOAuthHandlers(&referenceSpec, Muxer, false)
			referenceSpec.OAuthManager = thisOauthManager
		}

		proxy := TykNewSingleHostReverseProxy(remote)
		referenceSpec.target = remote

		proxyHandler := http.HandlerFunc(ProxyHandler(proxy, referenceSpec))
		tykMiddleware := TykMiddleware{referenceSpec, proxy}

		if referenceSpec.APIDefinition.UseKeylessAccess {
			// for KeyLessAccess we can't support rate limiting, versioning or access rules
			chain := alice.New(CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)
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

			// Use CreateMiddleware(&ModifiedMiddleware{tykMiddleware}, tykMiddleware)  to run custom middleware
			chain := alice.New(
				CreateMiddleware(&IPWhiteListMiddleware{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware),
				keyCheck,
				CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

			Muxer.Handle(referenceSpec.Proxy.ListenPath, chain)
		}

		ApiSpecRegister[referenceSpec.APIDefinition.APIID] = &referenceSpec

	}

}

// ReloadURLStructure will create a new muxer, reload all the app configs for an
// instance and then replace the DefaultServeMux with the new one, this enables a
// reconfiguration to take place without stopping any requests from being handled.
func ReloadURLStructure() {
	newMuxes := http.NewServeMux()
	loadAPIEndpoints(newMuxes)
	specs := getAPISpecs()
	loadApps(specs, newMuxes)

	http.DefaultServeMux = newMuxes
	log.Info("Reload complete")
}

func init() {
	intro()

	usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help      Show this screen
		--conf=FILE    Load a named configuration file
		--port=PORT    Listen on PORT (overrides confg file)
		--memprofile   Generate a memory profile
		--debug		   Enable Debug output

	`

	arguments, err := docopt.Parse(usage, nil, true, "v1.2.1", false, false)
	if err != nil {
		log.Warning("Error while parsing arguments: ", err)
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

}

func main() {
	displayConfig()

	if doMemoryProfile {
		log.Info("Memory profiling active")
		profileFile, _ = os.Create("tyk.mprof")
		defer profileFile.Close()
	}

	targetPort := fmt.Sprintf(":%d", config.ListenPort)
	loadAPIEndpoints(http.DefaultServeMux)

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
		go http.Serve(l, nil)

	} else {

		// Resume accepting connections in a new goroutine.
		log.Println("Resuming listening on", l.Addr())
		specs := getAPISpecs()
		loadApps(specs, http.DefaultServeMux)
		go http.Serve(l, nil)

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
