package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/TykTechnologies/tykcommon"
	"github.com/lonelycode/go-uuid/uuid"
)

var CommandModeOptions = map[string]bool{
	"--import-blueprint": true,
	"--import-swagger":   true,
	"--create-api":       true,
	"--org-id":           true,
	"--upstream-target":  true,
	"--as-mock":          true,
	"--for-api":          true,
	"--as-version":       true,
}

// ./tyk --import-blueprint=blueprint.json --create-api --org-id=<id> --upstream-target="http://widgets.com/api/"`
func HandleCommandModeArgs(arguments map[string]interface{}) {

	if arguments["--import-blueprint"] != nil {
		handleBluePrintMode(arguments)
	}

	if arguments["--import-swagger"] != nil {
		handleSwaggerMode(arguments)
	}

}

func handleBluePrintMode(arguments map[string]interface{}) {
	doCreate := arguments["--create-api"]
	inputFile := arguments["--import-blueprint"]
	if doCreate == true {
		upstreamVal := arguments["--upstream-target"]
		orgId := arguments["--org-id"]
		if upstreamVal != nil && orgId != nil {
			// Create the API with the blueprint
			bp, err := bluePrintLoadFile(inputFile.(string))
			if err != nil {
				log.Error("File load error: ", err)
				return
			}

			def, dErr := createDefFromBluePrint(bp, orgId.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
			if dErr != nil {
				log.Error("Failed to create API Defintition from file")
				return
			}

			printDef(def)
			return
		}

		log.Error("No upstream target or org ID defined, these are both required")

	} else {
		// Different branch, here we need an API Definition to modify
		forApiPath := arguments["--for-api"]
		if forApiPath == nil {
			log.Error("If ading to an API, the path to the defintiton must be listed")
			return
		}

		versionName := arguments["--as-version"]
		if versionName == nil {
			log.Error("No version defined for this import operation, please set an import ID using the --as-version flag")
			return
		}

		defFromFile, err := apiDefLoadFile(forApiPath.(string))
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

		insertErr := bp.InsertIntoAPIDefinitionAsVersion(versionData, defFromFile, versionName.(string))
		if insertErr != nil {
			log.Error("Insertion failed: ", insertErr)
			return
		}

		printDef(defFromFile)

	}
}

func printDef(def *tykcommon.APIDefinition) {
	asJson, err := json.MarshalIndent(def, "", "    ")
	if err != nil {
		log.Error("Marshalling failed: ", err)
	}

	// The id attribute is for BSON only and breaks the parser if it's empty, cull it here.
	fixed := strings.Replace(string(asJson), "    \"id\": \"\",", "", 1)
	fmt.Printf(fixed)
}

func createDefFromBluePrint(bp *BluePrintAST, orgId, upstreamURL string, as_mock bool) (*tykcommon.APIDefinition, error) {
	ad := tykcommon.APIDefinition{
		Name:             bp.Name,
		Active:           true,
		UseKeylessAccess: true,
		APIID:            uuid.NewUUID().String(),
		OrgID:            orgId,
	}
	ad.VersionDefinition.Key = "version"
	ad.VersionDefinition.Location = "header"
	ad.VersionData.Versions = make(map[string]tykcommon.VersionInfo)
	ad.Proxy.ListenPath = "/" + ad.APIID + "/"
	ad.Proxy.StripListenPath = true
	ad.Proxy.TargetURL = upstreamURL

	versionData, err := bp.ConvertIntoApiVersion(as_mock)
	if err != nil {
		log.Error("onversion into API Def failed: ", err)
	}

	bp.InsertIntoAPIDefinitionAsVersion(versionData, &ad, strings.Trim(bp.Name, " "))

	return &ad, nil
}

func bluePrintLoadFile(filePath string) (*BluePrintAST, error) {
	blueprint, astErr := GetImporterForSource(ApiaryBluePrint)

	if astErr != nil {
		log.Error("Couldn't get blueprint importer: ", astErr)
		return blueprint.(*BluePrintAST), astErr
	}

	bluePrintFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load blueprint file: ", err)
		return blueprint.(*BluePrintAST), err
	}

	readErr := blueprint.ReadString(string(bluePrintFileData))
	if readErr != nil {
		log.Error("Failed to decode object")
		return blueprint.(*BluePrintAST), readErr
	}

	return blueprint.(*BluePrintAST), nil
}

func apiDefLoadFile(filePath string) (*tykcommon.APIDefinition, error) {
	def := &tykcommon.APIDefinition{}

	defFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load API Definition file: ", err)
		return def, err
	}

	jsonErr := json.Unmarshal(defFileData, &def)
	if jsonErr != nil {
		log.Error("Failed to unmarshal the JSON definition: ", jsonErr)
		return def, jsonErr
	}

	return def, nil
}
