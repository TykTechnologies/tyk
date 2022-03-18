package main

import (
	"fmt"
	"net/http"

	tykctx "github.com/TykTechnologies/tyk/ctx"
)

func main() {}

func MyPluginFunction(w http.ResponseWriter, r *http.Request) {
	apidef := tykctx.GetDefinition(r)
	fmt.Println("API Definition is", apidef)

}
