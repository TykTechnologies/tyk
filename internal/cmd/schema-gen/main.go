package main

// This app reflects the known data model structs and generates
// various outputs based on the generator.
//
// - `jsonschema` generates a jsonschema for validation,
// - `structs` generates a custom json with go struct metadata.
//
// For each generator, the output is written out in schema/*.
//
// Usage:
//
// - `task schema-gen`
// - `go run internal/cmd/schema-gen/main.go (from root)

import (
	"fmt"
	"os"

	"github.com/TykTechnologies/tyk/internal/cmd/schema-gen/defaults"
	"github.com/TykTechnologies/tyk/internal/cmd/schema-gen/jsonschema"
	"github.com/TykTechnologies/tyk/internal/cmd/schema-gen/structs"
)

func main() {
	if err := start(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func start() (err error) {
	generators := []func() error{
		jsonschema.Dump,
		structs.Dump,
		defaults.Dump,
	}
	for _, generator := range generators {
		if err := generator(); err != nil {
			return err
		}
	}
	return nil
}
