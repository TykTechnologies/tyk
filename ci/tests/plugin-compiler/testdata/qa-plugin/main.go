package main

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/user"
)

var logger = log.Get()

// AddFooBarHeader adds custom "Foo: Bar" header to the request
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
}

// Custom Auth, applies a rate limit of
// 2 per 10 given a token of "abc"
func AuthCheck(rw http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "d3fd1a57-94ce-4a36-9dfe-679a8f493b49" && token != "3be61aa4-2490-4637-93b9-105001aa88a5" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	session := &user.SessionState{
		Alias: token,
		Rate:  2,
		Per:   10,
		MetaData: map[string]interface{}{
			token: token,
		},
		KeyID: token,
	}
	ctx.SetSession(r, session, true)
}
func main() {}
func init() {
	logger.Info("--- Go custom plugin v4 init success! ---- ")
}
