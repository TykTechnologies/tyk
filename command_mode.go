package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/importer"
)

var commandModeOptions = []string{
	"--import-blueprint",
	"--import-swagger",
	"--create-api",
	"--org-id",
	"--upstream-target",
	"--as-mock",
	"--for-api",
	"--as-version",
}

// ./tyk --import-blueprint=blueprint.json --create-api --org-id=<id> --upstream-target="http://widgets.com/api/"`
func handleCommandModeArgs(arguments map[string]interface{}) {
	if arguments["--import-blueprint"] != nil {
		if err := handleBluePrintMode(arguments); err != nil {
			log.Error(err)
		}
	}

	if arguments["--import-swagger"] != nil {
		if err := handleSwaggerMode(arguments); err != nil {
			log.Error(err)
		}
	}
}

func handleBluePrintMode(arguments map[string]interface{}) error {
	doCreate := arguments["--create-api"].(bool)
	inputFile := arguments["--import-blueprint"]
	if !doCreate {
		// Different branch, here we need an API Definition to modify
		forAPIPath := arguments["--for-api"]
		if forAPIPath == nil {
			return fmt.Errorf("If ading to an API, the path to the defintiton must be listed")
		}

		versionName := arguments["--as-version"]
		if versionName == nil {
			return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
		}

		defFromFile, err := apiDefLoadFile(forAPIPath.(string))
		if err != nil {
			return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
		}

		bp, err := bluePrintLoadFile(inputFile.(string))
		if err != nil {
			return fmt.Errorf("File load error: %v", err)
		}

		versionData, err := bp.ConvertIntoApiVersion(arguments["--as-mock"].(bool))
		if err != nil {
			return fmt.Errorf("onversion into API Def failed: %v", err)
		}

		if err := bp.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, versionName.(string)); err != nil {
			return fmt.Errorf("Insertion failed: %v", err)
		}

		printDef(defFromFile)

	}

	upstreamVal := arguments["--upstream-target"]
	orgID := arguments["--org-id"]

	if upstreamVal == nil && orgID == nil {
		return fmt.Errorf("No upstream target or org ID defined, these are both required")
	}

	// Create the API with the blueprint
	bp, err := bluePrintLoadFile(inputFile.(string))
	if err != nil {
		return fmt.Errorf("File load error: %v", err)
	}

	def, err := bp.ToAPIDefinition(orgID.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
	if err != nil {
		return fmt.Errorf("Failed to create API Defintition from file")
	}

	printDef(def)
	return nil
}

func handleSwaggerMode(arguments map[string]interface{}) error {
	doCreate := arguments["--create-api"]
	inputFile := arguments["--import-swagger"]
	if doCreate == true {
		upstreamVal := arguments["--upstream-target"]
		orgId := arguments["--org-id"]
		if upstreamVal != nil && orgId != nil {
			// Create the API with the blueprint
			s, err := swaggerLoadFile(inputFile.(string))
			if err != nil {
				return fmt.Errorf("File load error: %v", err)
			}

			def, err := s.ToAPIDefinition(orgId.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
			if err != nil {
				return fmt.Errorf("Failed to create API Defintition from file")
			}

			printDef(def)
			return nil
		}

		return fmt.Errorf("No upstream target or org ID defined, these are both required")

	} else {
		// Different branch, here we need an API Definition to modify
		forApiPath := arguments["--for-api"]
		if forApiPath == nil {
			return fmt.Errorf("If ading to an API, the path to the defintiton must be listed")
		}

		versionName := arguments["--as-version"]
		if versionName == nil {
			return fmt.Errorf("No version defined for this import operation, please set an import ID using the --as-version flag")
		}

		defFromFile, err := apiDefLoadFile(forApiPath.(string))
		if err != nil {
			return fmt.Errorf("failed to load and decode file data for API Definition: %v", err)
		}

		s, err := swaggerLoadFile(inputFile.(string))
		if err != nil {
			return fmt.Errorf("File load error: %v", err)
		}

		versionData, err := s.ConvertIntoApiVersion(arguments["--as-mock"].(bool))
		if err != nil {
			return fmt.Errorf("Conversion into API Def failed: %v", err)
		}

		if err := s.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, versionName.(string)); err != nil {
			return fmt.Errorf("Insertion failed: %v", err)
		}

		printDef(defFromFile)

	}
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
