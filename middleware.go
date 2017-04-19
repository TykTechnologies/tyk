package main

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gocraft/health"
	"github.com/justinas/alice"
	"github.com/paulbellamy/ratecounter"
)

var GlobalRate = ratecounter.NewRateCounter(1 * time.Second)

type TykMiddlewareImplementation interface {
	New()
	GetConfig() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	IsEnabledForSpec() bool
	GetName() string
}

func CreateDynamicMiddleware(name string, isPre, useSession bool, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		TykMiddleware:       tykMwSuper,
		MiddlewareClassName: name,
		Pre:                 isPre,
		UseSession:          useSession,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

func CreateDynamicAuthMiddleware(name string, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	return CreateDynamicMiddleware(name, true, false, tykMwSuper)
}

// Generic middleware caller to make extension easier
func CreateMiddleware(mw TykMiddlewareImplementation, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	// construct a new instance
	mw.New()

	// Pull the configuration
	mwConf, err := mw.GetConfig()
	if err != nil {
		log.Fatal("[Middleware] Configuration load failed")
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{
				"from_ip":  r.RemoteAddr,
				"method":   r.Method,
				"endpoint": r.URL.Path,
				"raw_url":  r.URL.String(),
				"size":     strconv.Itoa(int(r.ContentLength)),
				"mw_name":  mw.GetName(),
			}
			eventName := mw.GetName() + "." + "executed"
			job.EventKv("executed", meta)
			job.EventKv(eventName, meta)
			startTime := time.Now()

			if tykMwSuper.Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}
			err, errCode := mw.ProcessRequest(w, r, mwConf)
			if err != nil {
				handler := ErrorHandler{tykMwSuper}
				handler.HandleError(w, r, err.Error(), errCode)
				meta["error"] = err.Error()
				job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
				return
			}

			// Special code, stops execution
			if errCode == 1666 {
				// Stop
				log.Info("[Middleware] Received stop code")
				meta["stopped"] = "1"
				job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
				return
			}

			// Special code, bypasses all other execution
			if errCode != 666 {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			}

			job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
			job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
		})
	}
}

func AppendMiddleware(chain *[]alice.Constructor, mw TykMiddlewareImplementation, tykMwSuper *TykMiddleware) {
	if mw.IsEnabledForSpec() {
		*chain = append(*chain, CreateMiddleware(mw, tykMwSuper))
	}
}

func CheckCBEnabled(tykMwSuper *TykMiddleware) (used bool) {
	for _, v := range tykMwSuper.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			used = true
			tykMwSuper.Spec.CircuitBreakerEnabled = true
		}
	}
	return
}

func CheckETEnabled(tykMwSuper *TykMiddleware) (used bool) {
	for _, v := range tykMwSuper.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			used = true
			tykMwSuper.Spec.EnforcedTimeoutEnabled = true
		}
	}
	return
}

var responseProcessors = map[string]TykResponseHandler{
	"header_injector":         HeaderInjector{},
	"response_body_transform": ResponseTransformMiddleware{},
	"header_transform":        HeaderTransform{},
}

type TykResponseHandler interface {
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *SessionState) error
	New(interface{}, *APISpec) (TykResponseHandler, error)
}

func GetResponseProcessorByName(name string) (TykResponseHandler, error) {
	processor, ok := responseProcessors[name]
	if !ok {
		return nil, errors.New("Not found")
	}

	return processor, nil

}

type ResponseChain struct{}

func (r ResponseChain) Go(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	for _, rh := range chain {
		if err := rh.HandleResponse(rw, res, req, ses); err != nil {
			return err
		}
	}
	return nil
}
