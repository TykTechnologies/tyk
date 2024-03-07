package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/swagger"
)

func main() {
	r := openapi3.Reflector{
		Reflector: jsonschema.Reflector{},
	}
	r.DefaultOptions = append(r.DefaultOptions, jsonschema.StripDefinitionNamePrefix("Apidef"))

	r.Spec = &openapi3.Spec{Openapi: "3.0.3"}
	r.Spec.Info.
		WithTitle("Tyk Gateway API").
		WithVersion("5.2.3").
		WithDescription(" The Tyk Gateway API is the primary means for integrating your application with the Tyk API Gateway")
	err := swagger.APIS(&r)
	if err != nil {
		log.Fatal(err)
	}
	schema, err := r.Spec.MarshalYAML()
	if err != nil {
		log.Fatal(err)
	}
	err = writeSchema(schema, "open.yaml")
	if err != nil {
		log.Fatal(err)
	}
}

func writeSchema(schema []byte, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(schema)
	return err
}
