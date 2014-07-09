package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"
	"strings"
	"runtime/pprof"
)

type ApiError struct {
	Message string
}

// Proxies request onwards
func handler(p *httputil.ReverseProxy, apiSpec ApiSpec) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tm := TykMiddleware{apiSpec, p}
		handler := SuccessHandler{tm}
		// Skip all other execution
		handler.ServeHTTP(w, r)
		return

	}
}

func success_handler(w http.ResponseWriter, r *http.Request, p *httputil.ReverseProxy, spec ApiSpec) {
	if config.EnableAnalytics {
		t := time.Now()
		keyName := r.Header.Get(spec.ApiDefinition.Auth.AuthHeaderName)
		version := spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}
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
			t,
			version,
			spec.ApiDefinition.Name,
			spec.ApiDefinition.ApiId,
			spec.ApiDefinition.OrgId}
		analytics.RecordHit(thisRecord)
	}

	if spec.ApiDefinition.Proxy.StripListenPath {
		r.URL.Path = strings.Replace(r.URL.Path, spec.Proxy.ListenPath, "", 1)
	}

	p.ServeHTTP(w, r)

	if doMemoryProfile {
		pprof.WriteHeapProfile(prof_file)
	}
}

func handle_error(w http.ResponseWriter, r *http.Request, err string, err_code int, spec ApiSpec) {
	if config.EnableAnalytics {
		t := time.Now()
		keyName := r.Header.Get(spec.ApiDefinition.Auth.AuthHeaderName)
		version := spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}
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
			t,
			version,
			spec.ApiDefinition.Name,
			spec.ApiDefinition.ApiId,
			spec.ApiDefinition.OrgId}
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
