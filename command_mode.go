package main

import (
	"io/ioutil"
	"github.com/lonelycode/tykcommon"
	"code.google.com/p/go-uuid/uuid"
	"strings"
)

var CommandModeOptions = map[string]bool{
	"--import-blueprint": true,
	"--create-api": true,
	"--org-id": true,
	"--upstream-target": true,
	"--as-mock": true,
}

// ./tyk --import-blueprint=blueprint.json --create-api --org-id=<id> --upstream-target="http://widgets.com/api/"`
func HandleCommandModeArgs(arguments map[string]interface{}) {

	if arguments["--import-blueprint"] != nil {
		handleBluePrintMode(arguments)
	}

}

func handleBluePrintMode(arguments map[string]interface{}) {
	log.Info("Importing Blueprint")

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

			createDefFromBluePrint(bp, orgId.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
		}

		log.Error("No upstream target or org ID defined, these are both required")

	} else {
		// Different branch, here we need an API Definition to modify
	}
}

func createDefFromBluePrint(bp *BluePrintAST, orgId, upstreamURL string, as_mock bool) (*tykcommon.APIDefinition, error) {
	thisAD := tykcommon.APIDefinition{}
	thisAD.Name = bp.Name
	thisAD.Active = true
	thisAD.UseKeylessAccess = true
	thisAD.APIID = uuid.NewUUID().String()
	thisAD.OrgID = orgId
	thisAD.VersionDefinition.Key = "version"
	thisAD.VersionDefinition.Location  ="header"
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

	thisBlueprint.ReadString(string(bluePrintFileData))
	return thisBlueprint.(*BluePrintAST), nil
}
