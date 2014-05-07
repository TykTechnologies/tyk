package main

import(
	"fmt"
	"net/url"
	"net/http"
	"net/http/httputil"
	"github.com/Sirupsen/logrus"
)

/*
TODO: Set configuration file (Command line)
TODO: Configuration: set redis DB details
TODO: Redis storage manager
TODO: API endpoints for management functions: AddKey, RevokeKey, UpdateKey, GetKeyDetails, RequestKey (creates a key for user instead of self supplied)
TODO: Secure API endpoints (perhaps with just a shared secret, should be internally used anyway)
TODO: Configuration: Set shared secret
TODO: Configuration: Error template file path
TODO: Make SessionLimiter an interface so we can have different limiter types (e.g. queued requests?)
TODO: Add QuotaLimiter so time-based quotas can be added
*/


var log = logrus.New()
var authManager = AuthorisationManager{MockStorageManager{map[string]string{"1234": "{\"LastCheck\":1399469149,\"Allowance\":5.0,\"Rate\":1.0,\"Per\":1.0}"}}}
var sessionLimiter = SessionLimiter{}
var config = Config{}

func main() {
	LoadConfig("tyk.conf", &config)
	remote, err := url.Parse(config.TargetUrl)
	if err != nil {
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
					handle_error(w, r, "Rate limit exceeded")
				}
				authManager.UpdateSession(authHeaderValue, thisSessionState)
			} else {
				handle_error(w, r, "Key not authorised")
			}
		} else {
			handle_error(w, r, "Authorisation header missing")
		}
	}
}

func success_handler(w http.ResponseWriter, r *http.Request, p *httputil.ReverseProxy) {
	p.ServeHTTP(w, r)
}

func handle_error(w http.ResponseWriter, r *http.Request, err string) {
	// TODO: Set this as part of function call
	w.WriteHeader(400)
	// TODO: This should be a template
	fmt.Fprintf(w, "NOT AUTHORISED: %s", err)
}
