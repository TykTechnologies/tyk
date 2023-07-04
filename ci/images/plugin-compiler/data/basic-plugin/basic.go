package main

import (
	"net/http"
)

// MyPluginPre checks if session is NOT present, adds custom header
// with initial URI path and will be used as "pre" custom MW
func MyPluginPre(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusInternalServerError)
}
