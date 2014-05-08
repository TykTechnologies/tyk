package main

import(
	"fmt"
	"net/url"
	"net/http"
	"net/http/httputil"
	"github.com/Sirupsen/logrus"
	"github.com/docopt/docopt.go"
)

/*
TODO: Configuration: set redis DB details
TODO: Redis storage manager
TODO: API endpoints for management functions: AddKey, RevokeKey, UpdateKey, GetKeyDetails, RequestKey (creates a key for user instead of self supplied)
TODO: Secure API endpoints (perhaps with just a shared secret, should be internally used anyway)
TODO: Configuration: Set shared secret
TODO: Configuration: Error template file path
TODO: Add QuotaLimiter so time-based quotas can be added
*/


var log = logrus.New()
var authManager = AuthorisationManager{}
var sessionLimiter = SessionLimiter{}
var config = Config{}

func setupGlobals() {
	if config.Storage.Type == "memory" {
		authManager = AuthorisationManager{
			InMemoryStorageManager{
				map[string]string{}}}
	}
}

func init() {
	usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help      Show this screen
		--conf=FILE    Load a named configuration file
		--test         Create a test key

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

	test_value, _ := arguments["--test"].(bool)
	if test_value {
		log.Info("Adding test key: '1234' to storage map")
		authManager.Store.SetKey("1234", "{\"LastCheck\":1399469149,\"Allowance\":5.0,\"Rate\":1.0,\"Per\":1.0}")
	}

}

func main() {
	remote, err := url.Parse(config.TargetUrl)
	if err != nil {
		log.Error("Culdn't parse target URL")
		log.Error(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	http.HandleFunc(config.ListenPath, handler(proxy))
	targetPort := fmt.Sprintf(":%d", config.ListenPort)
	err = http.ListenAndServe(targetPort, nil)
	if err != nil {
		log.Error(err)
	}
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Check for API key existence
		authHeaderValue := r.Header.Get("authorisation")
		if authHeaderValue != "" {
			// Check if API key valid
			key_authorised, thisSessionState := authManager.IsKeyAuthorised(authHeaderValue)
			if key_authorised {
				// If valid, check if within rate limit
				forwardMessage := sessionLimiter.ForwardMessage(&thisSessionState)
				if forwardMessage {
					success_handler(w, r, p)
				} else {
					handle_error(w, r, "Rate limit exceeded", 429)
				}
				authManager.UpdateSession(authHeaderValue, thisSessionState)
			} else {
				handle_error(w, r, "Key not authorised", 403)
			}
		} else {
			handle_error(w, r, "Authorisation field missing", 400)
		}
	}
}

func success_handler(w http.ResponseWriter, r *http.Request, p *httputil.ReverseProxy) {
	p.ServeHTTP(w, r)
}

func handle_error(w http.ResponseWriter, r *http.Request, err string, err_code int) {
	w.WriteHeader(err_code)
	// TODO: This should be a template
	fmt.Fprintf(w, "NOT AUTHORISED: %s", err)
}
