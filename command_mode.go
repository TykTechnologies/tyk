package main

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tykcommon"
	"github.com/lonelycode/go-uuid/uuid"
	"io/ioutil"
	"strings"
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

		thisDefFromFile, fileErr := apiDefLoadFile(forApiPath.(string))
		if fileErr != nil {
			log.Error("failed to load and decode file data for API Definition: ", fileErr)
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

		insertErr := bp.InsertIntoAPIDefinitionAsVersion(versionData, &thisDefFromFile, versionName.(string))
		if insertErr != nil {
			log.Error("Insertion failed: ", insertErr)
			return
		}

		printDef(&thisDefFromFile)

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
	thisAD := tykcommon.APIDefinition{}
	thisAD.Name = bp.Name
	thisAD.Active = true
	thisAD.UseKeylessAccess = true
	thisAD.APIID = uuid.NewUUID().String()
	thisAD.OrgID = orgId
	thisAD.VersionDefinition.Key = "version"
	thisAD.VersionDefinition.Location = "header"
	thisAD.VersionData.Versions = make(map[string]tykcommon.VersionInfo)
	thisAD.VersionData.NotVersioned = false
	thisAD.Proxy.ListenPath = "/" + thisAD.APIID + "/"
	thisAD.Proxy.StripListenPath = true
	thisAD.Proxy.TargetURL = upstreamURL

	versionData, err := bp.ConvertIntoApiVersion(as_mock)
	if err != nil {
		log.Error("onversion into API Def failed: ", err)
	}

	bp.InsertIntoAPIDefinitionAsVersion(versionData, &thisAD, strings.Trim(bp.Name, " "))

	return &thisAD, nil
}

func bluePrintLoadFile(filePath string) (*BluePrintAST, error) {
	thisBlueprint, astErr := GetImporterForSource(ApiaryBluePrint)

	if astErr != nil {
		log.Error("Couldn't get blueprint importer: ", astErr)
		return thisBlueprint.(*BluePrintAST), astErr
	}

	bluePrintFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load blueprint file: ", err)
		return thisBlueprint.(*BluePrintAST), err
	}

	readErr := thisBlueprint.ReadString(string(bluePrintFileData))
	if readErr != nil {
		log.Error("Failed to decode object")
		return thisBlueprint.(*BluePrintAST), readErr
	}

	return thisBlueprint.(*BluePrintAST), nil
}

func apiDefLoadFile(filePath string) (tykcommon.APIDefinition, error) {
	thisDef := tykcommon.APIDefinition{}

	defFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load API Definition file: ", err)
		return thisDef, err
	}

	jsonErr := json.Unmarshal(defFileData, &thisDef)
	if jsonErr != nil {
		log.Error("Failed to unmarshal the JSON definition: ", jsonErr)
		return thisDef, jsonErr
	}

	return thisDef, nil
}
