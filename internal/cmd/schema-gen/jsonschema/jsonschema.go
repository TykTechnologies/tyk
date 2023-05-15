package jsonschema

import (
	"encoding/json"
	"os"

	"github.com/invopop/jsonschema"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func Dump() (err error) {
	// The Gateway Config
	err = dump("schema/jsonschema/config.json", jsonschema.Reflect(config.Config{}))
	if err != nil {
		return
	}

	// The API Definition
	err = dump("schema/jsonschema/apidef.json", jsonschema.Reflect(apidef.APIDefinition{}))
	if err != nil {
		return
	}

	// OAS API Tyk Extension
	err = dump("schema/jsonschema/x-tyk-gateway.json", jsonschema.Reflect(oas.XTykAPIGateway{}))
	if err != nil {
		return
	}

	return nil
}

func dump(filename string, data interface{}) error {
	println(filename)

	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, dataBytes, 0644) //nolint:gosec
}
