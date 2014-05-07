package main

import(
	"fmt"
	"net/url"
	"net/http"
	"net/http/httputil"
	"github.com/Sirupsen/logrus"
)

var log = logrus.New()
var authManager = AuthorisationManager{MockStorageManager{map[string]string{"1234": "{\"LastCheck\":1399469149,\"Allowance\":5.0,\"Rate\":1.0,\"Per\":1.0}"}}}
var sessionLimiter = SessionLimiter{}

func main() {
	remote, err := url.Parse("http://www.lonelycode.com")
	if err != nil {
		log.Error(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	http.HandleFunc("/", handler(proxy))
	err = http.ListenAndServe(":8080", nil)
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
