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
var authManager = AuthorisationManager{}
var config = Config{}
var templates = &template.Template{}
var analytics = RedisAnalyticsHandler{}
var profileFile = &os.File{}
var doMemoryProfile bool
var genericOsinStorage *RedisOsinStorageInterface

// Generic system error
const (
	E_SYSTEM_ERROR          string = "{\"status\": \"system error, please contact administrator\"}"
	OAUTH_AUTH_CODE_TIMEOUT int    = 60 * 60
	OAUTH_PREFIX            string = "oauth-data."
)

// Display introductory details
func intro() {
	fmt.Print("\n\n")
	fmt.Println(goterm.Bold(goterm.Color("Tyk.io Gateway API v1.0", goterm.GREEN)))
	fmt.Println(goterm.Bold(goterm.Color("=======================", goterm.GREEN)))
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
	if config.Storage.Type == "memory" {
		log.Warning("Using in-memory storage. Warning: this is not scalable.")
		authManager = AuthorisationManager{
			&InMemoryStorageManager{
				map[string]string{}}}
	} else if config.Storage.Type == "redis" {
		log.Info("Using Redis storage manager.")
		authManager = AuthorisationManager{
			&RedisStorageManager{KeyPrefix: "apikey-"}}

		authManager.Store.Connect()
	}

	if (config.EnableAnalytics == true) && (config.Storage.Type != "redis") {
		log.Panic("Analytics requires Redis Storage backend, please enable Redis in the tyk.conf file.")
	}

	if config.EnableAnalytics {
		AnalyticsStore := RedisStorageManager{KeyPrefix: "analytics-"}
		log.Info("Setting up analytics DB connection")

		if config.AnalyticsConfig.Type == "csv" {
			log.Info("Using CSV cache purge")
			analytics = RedisAnalyticsHandler{
				Store: &AnalyticsStore,
				Clean: &CSVPurger{&AnalyticsStore}}

		} else if config.AnalyticsConfig.Type == "mongo" {
			log.Info("Using MongoDB cache purge")
			analytics = RedisAnalyticsHandler{
				Store: &AnalyticsStore,
				Clean: &MongoPurger{&AnalyticsStore, nil}}
		}

		analytics.Store.Connect()
		go analytics.Clean.StartPurgeLoop(config.AnalyticsConfig.PurgeDelay)
	}

	genericOsinStorage = MakeNewOsinServer()

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
	Muxer.HandleFunc("/tyk/reload/", CheckIsAPIOwner(resetHandler))
	Muxer.HandleFunc("/tyk/oauth/clients/create", CheckIsAPIOwner(createOauthClient))
	Muxer.HandleFunc("/tyk/oauth/clients/", CheckIsAPIOwner(oAuthClientHandler))
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec APISpec, Muxer *http.ServeMux, test bool) {
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
	osinStorage := RedisOsinStorageInterface{&storageManager}

	if test {
		log.Warning("Adding test client")
		testClient := &osin.Client{
			Id:          "1234",
			Secret:      "aabbccdd",
			RedirectUri: "http://client.oauth.com",
		}
		osinStorage.SetClient(testClient.Id, testClient, false)
		log.Warning("Test client added")
	}
	osinServer := osin.NewServer(serverConfig, osinStorage)
	osinServer.AccessTokenGen = &AccessTokenGenTyk{}

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	Muxer.HandleFunc(apiAuthorizePath, CheckIsAPIOwner(oauthHandlers.HandleGenerateAuthCodeData))
	Muxer.HandleFunc(clientAuthPath, oauthHandlers.HandleAuthorizePassthrough)
	Muxer.HandleFunc(clientAccessPath, oauthHandlers.HandleAccessRequest)
}

// Create the individual API (app) specs based on live configurations and assign middleware
func loadApps(APISpecs []APISpec, Muxer *http.ServeMux) {
	// load the APi defs
	log.Info("Loading API configurations.")

	for _, spec := range APISpecs {
		// Create a new handler for each API spec
		remote, err := url.Parse(spec.APIDefinition.Proxy.TargetURL)
		if err != nil {
			log.Error("Culdn't parse target URL")
			log.Error(err)
		}

		if spec.UseOauth2 {
			addOAuthHandlers(spec, Muxer, false)
		}

		proxy := TykNewSingleHostReverseProxy(remote)
		spec.target = remote

		proxyHandler := http.HandlerFunc(ProxyHandler(proxy, spec))
		tykMiddleware := TykMiddleware{spec, proxy}

		if spec.APIDefinition.UseKeylessAccess {
			// for KeyLessAccess we can't support rate limiting, versioning or access rules
			chain := alice.New().Then(proxyHandler)
			Muxer.Handle(spec.Proxy.ListenPath, chain)

		} else {

			// Select the keying method to use for setting session states
			var keyCheck func(http.Handler) http.Handler

			if spec.APIDefinition.UseOauth2 {
				// Oauth2
				keyCheck = CreateMiddleware(&Oauth2KeyExists{tykMiddleware}, tykMiddleware)
			} else if spec.APIDefinition.UseBasicAuth {
				// Basic Auth
				keyCheck = BasicAuthKeyIsValid{tykMiddleware}.New()
			} else if spec.EnableSignatureChecking {
				// HMAC Auth
				keyCheck = HMACMiddleware{tykMiddleware}.New()
			} else {
				// Auth key
				keyCheck = CreateMiddleware(&AuthKey{tykMiddleware}, tykMiddleware)
			}

			// Use CreateMiddleware(&ModifiedMiddleware{tykMiddleware}, tykMiddleware)  to run custom middleware
			chain := alice.New(
				keyCheck,
				CreateMiddleware(&KeyExpired{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&VersionCheck{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&AccessRightsCheck{tykMiddleware}, tykMiddleware),
				CreateMiddleware(&RateLimitAndQuotaCheck{tykMiddleware}, tykMiddleware)).Then(proxyHandler)

			Muxer.Handle(spec.Proxy.ListenPath, chain)
		}

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

	arguments, err := docopt.Parse(usage, nil, true, "v1.0", false)
	if err != nil {
		log.Println("Error while parsing arguments.")
		log.Fatal(err)
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
	log.Level = logrus.Info
	if doDebug == true {
		log.Level = logrus.Debug
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
