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

const mwStatusRespond = 666

var GlobalRate = ratecounter.NewRateCounter(1 * time.Second)

type TykMiddleware interface {
	Init()
	Base() *BaseMiddleware
	GetConfig() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	IsEnabledForSpec() bool
	GetName() string
}

func CreateDynamicMiddleware(name string, isPre, useSession bool, baseMid *BaseMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		BaseMiddleware:      baseMid,
		MiddlewareClassName: name,
		Pre:                 isPre,
		UseSession:          useSession,
	}

	return CreateMiddleware(dMiddleware)
}

func CreateDynamicAuthMiddleware(name string, baseMid *BaseMiddleware) func(http.Handler) http.Handler {
	return CreateDynamicMiddleware(name, true, false, baseMid)
}

// Generic middleware caller to make extension easier
func CreateMiddleware(mw TykMiddleware) func(http.Handler) http.Handler {
	// construct a new instance
	mw.Init()

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

			if mw.Base().Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}
			err, errCode := mw.ProcessRequest(w, r, mwConf)
			if err != nil {
				handler := ErrorHandler{mw.Base()}
				handler.HandleError(w, r, err.Error(), errCode)
				meta["error"] = err.Error()
				job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
				return
			}

			// Special code, bypasses all other execution
			if errCode != mwStatusRespond {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			}

			job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
			job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
		})
	}
}

func AppendMiddleware(chain *[]alice.Constructor, mw TykMiddleware) {
	if mw.IsEnabledForSpec() {
		*chain = append(*chain, CreateMiddleware(mw))
	}
}

func CheckCBEnabled(baseMid *BaseMiddleware) bool {
	for _, v := range baseMid.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			baseMid.Spec.CircuitBreakerEnabled = true
			return true
		}
	}
	return false
}

func CheckETEnabled(baseMid *BaseMiddleware) bool {
	for _, v := range baseMid.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			baseMid.Spec.EnforcedTimeoutEnabled = true
			return true
		}
	}
	return false
}

type TykResponseHandler interface {
	Init(interface{}, *APISpec) error
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *SessionState) error
}

func GetResponseProcessorByName(name string) (TykResponseHandler, error) {
	switch name {
	case "header_injector":
		return &HeaderInjector{}, nil
	case "response_body_transform":
		return &ResponseTransformMiddleware{}, nil
	case "header_transform":
		return &HeaderTransform{}, nil
	default:
		return nil, errors.New("not found")
	}
}

func handleResponseChain(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	for _, rh := range chain {
		if err := rh.HandleResponse(rw, res, req, ses); err != nil {
			return err
		}
	}
	return nil
}
