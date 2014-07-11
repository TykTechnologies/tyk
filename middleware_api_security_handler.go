package main

import (
	"net/http"
	"fmt"
)

func CheckIsAPIOwner(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get("X-Tyk-Authorisation")
		if tykAuthKey != config.Secret {
			// Error
			log.Warning("Attempted administrative access with invalid or missing key!")

			responseMessage := createError("Method not supported")
			w.WriteHeader(403)
			fmt.Fprintf(w, string(responseMessage))

			return
		}

		handler(w, r)

	}
}
