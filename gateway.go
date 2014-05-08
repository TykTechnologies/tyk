package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
)

type ApiError struct {
	Message string
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Check for API key existence
		authHeaderValue := r.Header.Get("authorisation")
		if authHeaderValue != "" {
			// Check if API key valid
			key_authorised, thisSessionState := authManager.IsKeyAuthorised(authHeaderValue)
			keyExpired := authManager.IsKeyExpired(&thisSessionState)
			if key_authorised {
				if  !keyExpired {
					// If valid, check if within rate limit
					forwardMessage, reason := sessionLimiter.ForwardMessage(&thisSessionState)
					if forwardMessage {
						success_handler(w, r, p)
					} else {
						if reason == 1 {
							handle_error(w, r, "Rate limit exceeded", 429)
						} else if reason == 2 {
							handle_error(w, r, "Quota exceeded", 429)
						}

					}
					authManager.UpdateSession(authHeaderValue, thisSessionState)
				} else {
					handle_error(w, r, "Key has expired, please renew", 403)
				}
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
	thisError := ApiError{fmt.Sprintf("%s", err)}
	templates.ExecuteTemplate(w, "error.json", &thisError)
}
