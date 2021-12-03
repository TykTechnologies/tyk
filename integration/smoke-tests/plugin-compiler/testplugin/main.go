package main

import (
	"net/http"

	// Example of package which is not part of Gateway
	"github.com/kr/pretty"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
)

var logger = log.Get()

// AddFooBarHeader adds custom "Foo: Bar" header to the request
//nolint:deadcode
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
	logger.Info("Test")

	api := ctx.GetDefinition(r)
	if api != nil {
		logger.Info("API Definition", pretty.Sprint(api))
	}
}

func main() {}
