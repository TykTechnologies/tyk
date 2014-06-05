package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
	"runtime/pprof"
)

type ApiError struct {
	Message string
}

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		for _, sub := range config.ExcludePaths {
			if strings.Contains(r.URL.Path, sub) {
				success_handler(w, r, p)
				return
			}
		}

		// Check for API key existence
		authHeaderValue := r.Header.Get(config.AuthHeaderName)
		if authHeaderValue != "" {
			// Check if API key valid
			key_authorised, thisSessionState := authManager.IsKeyAuthorised(authHeaderValue)
			keyExpired := authManager.IsKeyExpired(&thisSessionState)
			if key_authorised {
				if !keyExpired {
					// If valid, check if within rate limit
					forwardMessage, reason := sessionLimiter.ForwardMessage(&thisSessionState)
					if forwardMessage {
						success_handler(w, r, p)
					} else {
						if reason == 1 {
							log.WithFields(logrus.Fields{
								"path":   r.URL.Path,
								"origin": r.RemoteAddr,
								"key":    authHeaderValue,
							}).Info("Key rate limit exceeded.")
							handle_error(w, r, "Rate limit exceeded", 409)
						} else if reason == 2 {
							log.WithFields(logrus.Fields{
								"path":   r.URL.Path,
								"origin": r.RemoteAddr,
								"key":    authHeaderValue,
							}).Info("Key quota limit exceeded.")
							handle_error(w, r, "Quota exceeded", 409)
						}

					}
					authManager.UpdateSession(authHeaderValue, thisSessionState)
				} else {
					log.WithFields(logrus.Fields{
						"path":   r.URL.Path,
						"origin": r.RemoteAddr,
						"key":    authHeaderValue,
					}).Info("Attempted access from expired key.")
					handle_error(w, r, "Key has expired, please renew", 403)
				}
			} else {
				log.WithFields(logrus.Fields{
					"path":   r.URL.Path,
					"origin": r.RemoteAddr,
					"key":    authHeaderValue,
				}).Info("Attempted access with non-existent key.")
				handle_error(w, r, "Key not authorised", 403)
			}
		} else {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": r.RemoteAddr,
			}).Info("Attempted access with malformed header, no auth header found.")
			handle_error(w, r, "Authorisation field missing", 400)
		}
	}
}

func success_handler(w http.ResponseWriter, r *http.Request, p *httputil.ReverseProxy) {
	if config.EnableAnalytics {
		t := time.Now()
		keyName := r.Header.Get(config.AuthHeaderName)
		thisRecord := AnalyticsRecord{
			r.Method,
			r.URL.Path,
			r.ContentLength,
			r.Header.Get("User-Agent"),
			t.Day(),
			t.Month(),
			t.Year(),
			t.Hour(),
			200,
			keyName,
			t}
		analytics.RecordHit(thisRecord)
	}
	p.ServeHTTP(w, r)
	if doMemoryProfile {
		pprof.WriteHeapProfile(prof_file)
	}
}

func handle_error(w http.ResponseWriter, r *http.Request, err string, err_code int) {
	if config.EnableAnalytics {
		t := time.Now()
		keyName := r.Header.Get(config.AuthHeaderName)
		thisRecord := AnalyticsRecord{
			r.Method,
			r.URL.Path,
			r.ContentLength,
			r.Header.Get("User-Agent"),
			t.Day(),
			t.Month(),
			t.Year(),
			t.Hour(),
			err_code,
			keyName,
			t}
		analytics.RecordHit(thisRecord)
	}

	w.WriteHeader(err_code)
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("X-Generator", "tyk.io")
	thisError := ApiError{fmt.Sprintf("%s", err)}
	templates.ExecuteTemplate(w, "error.json", &thisError)
	if doMemoryProfile {
		pprof.WriteHeapProfile(prof_file)
	}
}
