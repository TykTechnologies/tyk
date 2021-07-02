package main

import (
	"net/http"
	"html/template"

	"gopkg.in/Masterminds/sprig.v2"

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
		logger.Info("API Definition", api)
	}

	// Set up variables and template.
	tpl := `Hello {{.Name | trim | lower}}`

	// Get the Sprig function map.
	template.Must(template.New("test").Funcs(sprig.FuncMap()).Parse(tpl))
}

func main() {}
