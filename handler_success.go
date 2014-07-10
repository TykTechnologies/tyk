package main

import (
	"github.com/gorilla/context"
	"net/http"
	"net/http/httputil"
	"runtime/pprof"
	"strings"
	"time"
)

type ContextKey int

const (
	SessionData     = 0
	AuthHeaderValue = 1
)

type TykMiddleware struct {
	Spec  ApiSpec
	Proxy *httputil.ReverseProxy
}

type SuccessHandler struct {
	TykMiddleware
}

func (s SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if config.EnableAnalytics {
		t := time.Now()
		keyName := r.Header.Get(s.Spec.ApiDefinition.Auth.AuthHeaderName)
		version := s.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		if s.Spec.ApiDefinition.Proxy.StripListenPath {
			r.URL.Path = strings.Replace(r.URL.Path, s.Spec.Proxy.ListenPath, "", 1)
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
			s.Spec.ApiDefinition.Name,
			s.Spec.ApiDefinition.APIID,
			s.Spec.ApiDefinition.OrgID}
		analytics.RecordHit(thisRecord)
	}

	s.Proxy.ServeHTTP(w, r)

	if doMemoryProfile {
		pprof.WriteHeapProfile(prof_file)
	}

	context.Clear(r)
}
