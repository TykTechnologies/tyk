package main

import "net/http"

import ()

type TykMiddlewareImplementation interface {
	New()
	GetConfig() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request,  configuration interface{}) (error, int) // Handles request
}

// Generic middleware caller to make extension easier
func CreateMiddleware(mw TykMiddlewareImplementation, tykMwSuper TykMiddleware) func(http.Handler) http.Handler {
	aliceHandler := func(h http.Handler) http.Handler {
		thisHandler := func(w http.ResponseWriter, r *http.Request) {

			// construct a new instance
			mw.New()

			// Pull the configuration
			thisMwConfiguration, confErr := mw.GetConfig()

			if confErr != nil {
				handler := ErrorHandler{tykMwSuper}
				handler.HandleError(w, r, confErr.Error(), 403)
				return
			}

			// Process the Request
			if reqErr, errCode := mw.ProcessRequest(w, r, thisMwConfiguration); reqErr != nil {
				handler := ErrorHandler{tykMwSuper}
				handler.HandleError(w, r, reqErr.Error(), errCode)
				return
			}

			// No error, carry on...
			h.ServeHTTP(w, r)
		}

		return http.HandlerFunc(thisHandler)
	}

	return aliceHandler
}
