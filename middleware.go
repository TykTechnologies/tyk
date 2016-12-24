package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gocraft/health"
	"github.com/paulbellamy/ratecounter"
)

var GlobalRate *ratecounter.RateCounter = ratecounter.NewRateCounter(1 * time.Second)

type TykMiddlewareImplementation interface {
	New()
	GetConfig() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) // Handles request
	IsEnabledForSpec() bool
	GetName() string
}

func CreateDynamicMiddleware(MiddlewareName string, IsPre, UseSession bool, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		TykMiddleware:       tykMwSuper,
		MiddlewareClassName: MiddlewareName,
		Pre:                 IsPre,
		UseSession:          UseSession,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

func CreateDynamicAuthMiddleware(MiddlewareName string, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		TykMiddleware:       tykMwSuper,
		MiddlewareClassName: MiddlewareName,
		Auth:                true,
		UseSession:          false,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

// Generic middleware caller to make extension easier
func CreateMiddleware(mw TykMiddlewareImplementation, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	// construct a new instance
	mw.New()

	// Pull the configuration
	thisMwConfiguration, confErr := mw.GetConfig()

	if confErr != nil {
		log.Fatal("[Middleware] Configuration load failed")
		//handler := ErrorHandler{tykMwSuper}
		//handler.HandleError(w, r, confErr.Error(), 403)
	}

	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {
			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{
				"from_ip":  fmt.Sprint(r.RemoteAddr),
				"method":   r.Method,
				"endpoint": r.URL.Path,
				"raw_url":  r.URL.String(),
				"size":     strconv.Itoa(int(r.ContentLength)),
				"mw_name":  mw.GetName(),
			}
			job.EventKv("executed", meta)
			startTime := time.Now()

			if (tykMwSuper.Spec.CORS.OptionsPassthrough) && (r.Method == "OPTIONS") {
				h.ServeHTTP(w, r)
			} else {
				reqErr, errCode := mw.ProcessRequest(w, r, thisMwConfiguration)
				if reqErr != nil {
					handler := ErrorHandler{tykMwSuper}
					handler.HandleError(w, r, reqErr.Error(), errCode)
					meta["error"] = reqErr.Error()
					job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
					return
				}

				// Special code, stops execution
				if errCode == 1666 {
					// Stop
					log.Info("[Middleware] Received stop code")
					meta["stopped"] = "1"
					job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
					return
				}

				// Special code, bypasses all other execution
				if errCode != 666 {
					// No error, carry on...
					meta["bypass"] = "1"
					h.ServeHTTP(w, r)
				}

				job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
			}

		}

		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}
