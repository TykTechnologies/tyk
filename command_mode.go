package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/importer"
)

var commandModeOptions = []interface{}{
	importBlueprint,
	importSwagger,
	createAPI,
	orgID,
	upstreamTarget,
	asMock,
	forAPI,
	asVersion,
}

// ./tyk --import-blueprint=blueprint.json --create-api --org-id=<id> --upstream-target="http://widgets.com/api/"`
func handleCommandModeArgs() {
	if *importBlueprint != "" {
		if err := handleBluePrintMode(); err != nil {
			log.Error(err)
		}
	}

	if *importSwagger != "" {
		if err := handleSwaggerMode(); err != nil {
			log.Error(err)
		}
	}
}

func handleBluePrintMode() error {
	if !*createAPI {
		// Different branch, here we need an API Definition to modify
		if *forAPI == "" {
			return fmt.Errorf("If adding to an API, the path to the definition must be listed")
		}

		if *asVersion == "" {
			return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
		}

		defFromFile, err := apiDefLoadFile(*forAPI)
		if err != nil {
			return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
		}

		bp, err := bluePrintLoadFile(*importBlueprint)
		if err != nil {
			return fmt.Errorf("File load error: %v", err)
		}
		versionData, err := bp.ConvertIntoApiVersion(*asMock)
		if err != nil {
			return fmt.Errorf("onversion into API Def failed: %v", err)
		}

		if err := bp.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, *asVersion); err != nil {
			return fmt.Errorf("Insertion failed: %v", err)
		}

		printDef(defFromFile)

	}

	if *upstreamTarget == "" && *orgID == "" {
		return fmt.Errorf("No upstream target or org ID defined, these are both required")
	}

	// Create the API with the blueprint
	bp, err := bluePrintLoadFile(*importBlueprint)
	if err != nil {
		return fmt.Errorf("File load error: %v", err)
	}

	def, err := bp.ToAPIDefinition(*orgID, *upstreamTarget, *asMock)
	if err != nil {
		return fmt.Errorf("Failed to create API Definition from file")
	}

	printDef(def)
	return nil
}

func handleSwaggerMode() error {
	if *createAPI {
		if *upstreamTarget != "" && *orgID != "" {
			// Create the API with the blueprint
			s, err := swaggerLoadFile(*importSwagger)
			if err != nil {
				return fmt.Errorf("File load error: %v", err)
			}

			def, err := s.ToAPIDefinition(*orgID, *upstreamTarget, *asMock)
			if err != nil {
				return fmt.Errorf("Failed to create API Defintition from file")
			}

			printDef(def)
			return nil
		}

		return fmt.Errorf("No upstream target or org ID defined, these are both required")

	}

	// Different branch, here we need an API Definition to modify
	if *forAPI == "" {
		return fmt.Errorf("If adding to an API, the path to the definition must be listed")
	}

	if *asVersion == "" {
		return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
	}

	defFromFile, err := apiDefLoadFile(*forAPI)
	if err != nil {
		return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
	}

	s, err := swaggerLoadFile(*importSwagger)
	if err != nil {
		return fmt.Errorf("File load error: %v", err)
	}

	versionData, err := s.ConvertIntoApiVersion(*asMock)
	if err != nil {
		return fmt.Errorf("Conversion into API Def failed: %v", err)
	}

	if err := s.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, *asVersion); err != nil {
		return fmt.Errorf("Insertion failed: %v", err)
	}

	printDef(defFromFile)

	return nil
}

func printDef(def *apidef.APIDefinition) {
	asJSON, err := json.MarshalIndent(def, "", "    ")
	if err != nil {
		log.Error("Marshalling failed: ", err)
	}

	// The id attribute is for BSON only and breaks the parser if it's empty, cull it here.
	fixed := strings.Replace(string(asJSON), `    "id": "",`, "", 1)
	fmt.Println(fixed)
}

func swaggerLoadFile(path string) (*importer.SwaggerAST, error) {
	swagger, err := importer.GetImporterForSource(importer.SwaggerSource)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := swagger.LoadFrom(f); err != nil {
		return nil, err
	}

	return swagger.(*importer.SwaggerAST), nil
}

func bluePrintLoadFile(path string) (*importer.BluePrintAST, error) {
	blueprint, err := importer.GetImporterForSource(importer.ApiaryBluePrint)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := blueprint.LoadFrom(f); err != nil {
		return nil, err
	}

	return blueprint.(*importer.BluePrintAST), nil
}

func apiDefLoadFile(path string) (*apidef.APIDefinition, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	def := &apidef.APIDefinition{}
	if err := json.NewDecoder(f).Decode(&def); err != nil {
		return nil, err
	}
	return def, nil
}
