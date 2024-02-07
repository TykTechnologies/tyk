package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/invopop/jsonschema"
	log "github.com/sirupsen/logrus"
)

func main() {
	ref := jsonschema.Reflector{
		Namer: func(r reflect.Type) string {
			if r.Name() != "" {
				return fmt.Sprintf("X-Tyk-%s", r.Name())
			}
			return r.Name()
		},
		ExpandedStruct: true,
	}

	err := ref.AddGoComments("github.com/TykTechnologies/tyk/", "apidef/oas/")
	if err != nil {
		log.Println("error adding comments")
	}

	schema := ref.Reflect(&oas.XTykAPIGateway{})
	out, err := schema.MarshalJSON()
	if err != nil {
		log.Fatal("error generating schema")
	}

	outMap := map[string]interface{}{}
	_ = json.Unmarshal(out, &outMap)

	out, _ = json.MarshalIndent(outMap, "", "  ")

	out = bytes.Replace(out, []byte("$defs"), []byte("definitions"), -1)
	err = os.WriteFile("apidef/oas/schema/x-tyk-api-gateway.json", out, 0644)
	if err != nil {
		log.Fatal("error writing generated schema")
	}
}
