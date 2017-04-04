package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/lonelycode/go-uuid/uuid"

	"github.com/TykTechnologies/tyk/apidef"
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
		handleBluePrintMode(arguments)
	}

	if arguments["--import-swagger"] != nil {
		handleSwaggerMode(arguments)
	}
}

func handleBluePrintMode(arguments map[string]interface{}) {
	doCreate := arguments["--create-api"].(bool)
	inputFile := arguments["--import-blueprint"]
	if !doCreate {
		// Different branch, here we need an API Definition to modify
		forAPIPath := arguments["--for-api"]
		if forAPIPath == nil {
			log.Error("If ading to an API, the path to the defintiton must be listed")
			return
		}

		versionName := arguments["--as-version"]
		if versionName == nil {
			log.Error("No version defined for this import operation, please set an import ID using the --as-version flag")
			return
		}

		defFromFile, err := apiDefLoadFile(forAPIPath.(string))
		if err != nil {
			log.Error("failed to load and decode file data for API Definition: ", err)
			return
		}

		bp, err := bluePrintLoadFile(inputFile.(string))
		if err != nil {
			log.Error("File load error: ", err)
			return
		}

		versionData, err := bp.ConvertIntoApiVersion(arguments["--as-mock"].(bool))
		if err != nil {
			log.Error("onversion into API Def failed: ", err)
		}

		if err := bp.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, versionName.(string)); err != nil {
			log.Error("Insertion failed: ", err)
			return
		}

		printDef(defFromFile)

	}

	upstreamVal := arguments["--upstream-target"]
	orgID := arguments["--org-id"]

	if upstreamVal == nil && orgID == nil {
		log.Error("No upstream target or org ID defined, these are both required")
		return
	}

	// Create the API with the blueprint
	bp, err := bluePrintLoadFile(inputFile.(string))
	if err != nil {
		log.Error("File load error: ", err)
		return
	}

	def, err := createDefFromBluePrint(bp, orgID.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
	if err != nil {
		log.Error("Failed to create API Defintition from file")
		return
	}

	printDef(def)
	return
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

func createDefFromBluePrint(bp *BluePrintAST, orgID, upstreamURL string, asMock bool) (*apidef.APIDefinition, error) {
	ad := apidef.APIDefinition{
		Name:             bp.Name,
		Active:           true,
		UseKeylessAccess: true,
		APIID:            uuid.NewUUID().String(),
		OrgID:            orgID,
	}
	ad.VersionDefinition.Key = "version"
	ad.VersionDefinition.Location = "header"
	ad.VersionData.Versions = make(map[string]apidef.VersionInfo)
	ad.Proxy.ListenPath = "/" + ad.APIID + "/"
	ad.Proxy.StripListenPath = true
	ad.Proxy.TargetURL = upstreamURL

	versionData, err := bp.ConvertIntoApiVersion(asMock)
	if err != nil {
		log.Error("onversion into API Def failed: ", err)
	}

	err = bp.InsertIntoAPIDefinitionAsVersion(versionData, &ad, strings.Trim(bp.Name, " "))

	return &ad, err
}

func bluePrintLoadFile(filePath string) (*BluePrintAST, error) {
	blueprint, err := GetImporterForSource(ApiaryBluePrint)
	if err != nil {
		log.Error("Couldn't get blueprint importer: ", err)
		return blueprint.(*BluePrintAST), err
	}

	bluePrintFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load blueprint file: ", err)
		return blueprint.(*BluePrintAST), err
	}

	if err := blueprint.ReadString(string(bluePrintFileData)); err != nil {
		log.Error("Failed to decode object")
		return blueprint.(*BluePrintAST), err
	}

	return blueprint.(*BluePrintAST), nil
}

func apiDefLoadFile(filePath string) (*apidef.APIDefinition, error) {
	def := &apidef.APIDefinition{}

	defFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load API Definition file: ", err)
		return def, err
	}

	if err := json.Unmarshal(defFileData, &def); err != nil {
		log.Error("Failed to unmarshal the JSON definition: ", err)
		return def, err
	}

	return def, nil
}
