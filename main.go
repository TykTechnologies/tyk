package main

import (
        "fmt"
        "github.com/Sirupsen/logrus"
        "github.com/buger/goterm"
        "github.com/docopt/docopt.go"
        "html/template"
        "net/http"
        "net/http/httputil"
        "net/url"
        "os"
        "strconv"
	"github.com/rcrowley/goagain"
	"net"
	"time"
	"github.com/justinas/alice"
)

var log = logrus.New()
var authManager = AuthorisationManager{}
var sessionLimiter = SessionLimiter{}
var config = Config{}
var templates = &template.Template{}
var systemError string = "{\"status\": \"system error, please contact administrator\"}"
var analytics = RedisAnalyticsHandler{}
var prof_file = &os.File{}
var doMemoryProfile bool

func displayConfig() {
        config_table := goterm.NewTable(0, 10, 5, ' ', 0)
        fmt.Fprintf(config_table, "Listening on port:\t%d\n", config.ListenPort)

        fmt.Println(config_table)
        fmt.Println("")
}

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
                                Store:  &AnalyticsStore,
                                Clean:  &CSVPurger{&AnalyticsStore}}

                } else if config.AnalyticsConfig.Type == "mongo" {
                        log.Info("Using MongoDB cache purge")
                        analytics = RedisAnalyticsHandler{
                                Store:  &AnalyticsStore,
                                Clean:  &MongoPurger{&AnalyticsStore, nil}}
                }

                analytics.Store.Connect()
                go analytics.Clean.StartPurgeLoop(config.AnalyticsConfig.PurgeDelay)
        }

        template_file := fmt.Sprintf("%s/error.json", config.TemplatePath)
        templates = template.Must(template.ParseFiles(template_file))
}

func init() {
        usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help      Show this screen
		--conf=FILE    Load a named configuration file
		--port=PORT    Listen on PORT (overrides confg file)
		--memprofile   Generate a memory profile

	`

        arguments, err := docopt.Parse(usage, nil, true, "Tyk v1.0", false)
        if err != nil {
                log.Println("Error while parsing arguments.")
                log.Fatal(err)
        }

        filename := "tyk.conf"
        value, _ := arguments["--conf"]
        if value != nil {
                log.Info(fmt.Sprintf("Using %s for configuration", value.(string)))
                filename = arguments["--conf"].(string)
        } else {
                log.Info("No configuration file defined, will try to use default (./tyk.conf)")
        }

        loadConfig(filename, &config)

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

}

func intro() {
        fmt.Print("\n\n")
        fmt.Println(goterm.Bold(goterm.Color("Tyk.io Gateway API v0.1", goterm.GREEN)))
        fmt.Println(goterm.Bold(goterm.Color("=======================", goterm.GREEN)))
        fmt.Print("Copyright Jively Ltd. 2014")
        fmt.Print("\nhttp://www.tyk.io\n\n")
}

func loadApiEndpoints(Muxer *http.ServeMux) {
	// set up main API handlers
	Muxer.HandleFunc("/tyk/keys/create", securityHandler(createKeyHandler))
	Muxer.HandleFunc("/tyk/keys/", securityHandler(keyHandler))
	Muxer.HandleFunc("/tyk/reload/", securityHandler(resetHandler))
}

func getApiSpecs() []ApiSpec {
	var ApiSpecs []ApiSpec
	thisApiLoader := ApiDefinitionLoader{}

	if config.UseDBAppConfigs {
		log.Info("Using App Configuration from Mongo DB")
		ApiSpecs = thisApiLoader.LoadDefinitionsFromMongo()
	} else {
		ApiSpecs = thisApiLoader.LoadDefinitions("./apps/")
	}

	return ApiSpecs
}

func customHandler1(h http.Handler) http.Handler {
	thisHandler := func(w http.ResponseWriter, r *http.Request) {
		log.Info("Middlwware 1 called!")
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(thisHandler)
}

func customHandler2(h http.Handler) http.Handler {
	thisHandler := func(w http.ResponseWriter, r *http.Request) {
		log.Info("Middlwware 2 called!")
		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(thisHandler)
}

type StructMiddleware struct{
	spec ApiSpec
}

func (s StructMiddleware) New(spec ApiSpec) func(http.Handler) http.Handler {
	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {
			log.Info("Middlwware 3 called!")
			log.Info(spec.ApiId)
			h.ServeHTTP(w, r)
		}
		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}

func loadApps(ApiSpecs []ApiSpec, Muxer *http.ServeMux) {
	// load the APi defs
	log.Info("Loading API configurations.")

	for _, spec := range(ApiSpecs) {
		// Create a new handler for each API spec
		remote, err := url.Parse(spec.ApiDefinition.Proxy.TargetUrl)
		if err != nil {
			log.Error("Culdn't parse target URL")
			log.Error(err)
		}
		log.Info(remote)
		proxy := httputil.NewSingleHostReverseProxy(remote)

		myHandler := http.HandlerFunc(handler(proxy, spec))
		tykMiddleware := TykMiddleware{spec, proxy}

		chain := alice.New(
			VersionCheck{tykMiddleware}.New(),
			KeyExists{tykMiddleware}.New(),
			AccessRightsCheck{tykMiddleware}.New(),
			KeyExpired{tykMiddleware}.New(),
			RateLimitAndQuotaCheck{tykMiddleware}.New()).Then(myHandler)
		Muxer.Handle(spec.Proxy.ListenPath, chain)
	}
}

func ReloadURLStructure() {
	newMuxes := http.NewServeMux()
	loadApiEndpoints(newMuxes)
	specs := getApiSpecs()
	loadApps(specs, newMuxes)

	http.DefaultServeMux = newMuxes
	log.Info("Reload complete")
}

func main() {
        intro()
        displayConfig()

        if doMemoryProfile {
                log.Info("Memory profiling active")
                prof_file, _ = os.Create("tyk.mprof")
                defer prof_file.Close()
        }

        targetPort := fmt.Sprintf(":%d", config.ListenPort)
	loadApiEndpoints(http.DefaultServeMux)

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
		specs := getApiSpecs()
		loadApps(specs, http.DefaultServeMux)
		go http.Serve(l, nil)

	} else {

		// Resume accepting connections in a new goroutine.
		log.Println("Resuming listening on", l.Addr())
		specs := getApiSpecs()
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
