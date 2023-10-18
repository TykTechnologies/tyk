package main

import (
	"html/template"
	"net/http"

	"github.com/Masterminds/sprig/v3"
	// Example of package which is not part of Gateway
	"github.com/kr/pretty"
	jose "github.com/go-jose/go-jose"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
)

type encrypter jose.Encrypter

var logger = log.Get()

// AddFooBarHeader adds custom "Foo: Bar" header to the request
//
//nolint:deadcode
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
	logger.Info("Test")

	api := ctx.GetDefinition(r)
	if api != nil {
		logger.Info("API Definition", pretty.Sprint(api))
	}

	// Set up variables and template.
	tpl := `Hello {{.Name | trim | lower}}`

	// Get the Sprig function map.
	template.Must(template.New("test").Funcs(sprig.FuncMap()).Parse(tpl))
}

func main() {}
