package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/TykTechnologies/tykcommon"
	"github.com/lonelycode/go-uuid/uuid"
)

const (
	SwaggerSource APIImporterSource = "swagger"
)

type DefinitionObjectFormatAST struct {
	Format string `json:"format"`
	Type   string `json:"type"`
}

type DefinitionObjectAST struct {
	Type       string                               `json:"type"`
	Required   []string                             `json:"required"`
	Properties map[string]DefinitionObjectFormatAST `json:"properties"`
}

type ResponseCodeObjectAST struct {
	Description string `json:"description"`
	Schema      struct {
		Items map[string]interface{} `json:"items"`
		Type  string                 `json:"type"`
	} `json:"schema"`
}

type PathMethodObject struct {
	Description string                           `json:"description"`
	OperationID string                           `json:"operationId"`
	Responses   map[string]ResponseCodeObjectAST `json:"responses"`
}

type PathItemObject struct {
	Get     PathMethodObject `json:"get"`
	Put     PathMethodObject `json:"put"`
	Post    PathMethodObject `json:"post"`
	Patch   PathMethodObject `json:"patch"`
	Options PathMethodObject `json:"options"`
	Delete  PathMethodObject `json:"delete"`
	Head    PathMethodObject `json:"head"`
}

type SwaggerAST struct {
	BasePath    string                         `json:"basePath"`
	Consumes    []string                       `json:"consumes"`
	Definitions map[string]DefinitionObjectAST `json:"definitions"`
	Host        string                         `json:"host"`
	Info        struct {
		Contact struct {
			Email string `json:"email"`
			Name  string `json:"name"`
			URL   string `json:"url"`
		} `json:"contact"`
		Description string `json:"description"`
		License     struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"license"`
		TermsOfService string `json:"termsOfService"`
		Title          string `json:"title"`
		Version        string `json:"version"`
	} `json:"info"`
	Paths    map[string]PathItemObject `json:"paths"`
	Produces []string                  `json:"produces"`
	Schemes  []string                  `json:"schemes"`
	Swagger  string                    `json:"swagger"`
}

func (s *SwaggerAST) ReadString(asJson string) error {
	marshallErr := json.Unmarshal([]byte(asJson), &s)
	if marshallErr != nil {
		log.Error("Marshalling failed: ", marshallErr)
		return marshallErr
	}

	return nil
}

func (s *SwaggerAST) ConvertIntoApiVersion(asMock bool) (tykcommon.VersionInfo, error) {
	thisVersionInfo := tykcommon.VersionInfo{}

	if asMock {
		return thisVersionInfo, errors.New("Swagger mocks not supported")
	}

	thisVersionInfo.UseExtendedPaths = true
	thisVersionInfo.Name = s.Info.Version
	thisVersionInfo.ExtendedPaths.WhiteList = make([]tykcommon.EndPointMeta, 0)

	if len(s.Paths) == 0 {
		return thisVersionInfo, errors.New("No paths defined in swagger file!")
	}
	for pathName, pathSpec := range s.Paths {
		log.Debug("path: %s", pathName)
		newEndpointMeta := tykcommon.EndPointMeta{}
		newEndpointMeta.MethodActions = make(map[string]tykcommon.EndpointMethodMeta)
		newEndpointMeta.Path = pathName

		// We just want the paths here, no mocks
		methods := map[string]PathMethodObject{
			"GET":     pathSpec.Get,
			"PUT":     pathSpec.Put,
			"POST":    pathSpec.Post,
			"HEAD":    pathSpec.Head,
			"PATCH":   pathSpec.Patch,
			"OPTIONS": pathSpec.Options,
			"DELETE":  pathSpec.Delete,
		}
		for methodName, m := range methods {
			// skip methods that are not defined
			if len(m.Responses) == 0 && m.Description == "" && m.OperationID == "" {
				continue
			}
			thisMethodAction := tykcommon.EndpointMethodMeta{}
			thisMethodAction.Action = tykcommon.NoAction
			newEndpointMeta.MethodActions[methodName] = thisMethodAction
		}

		thisVersionInfo.ExtendedPaths.WhiteList = append(thisVersionInfo.ExtendedPaths.WhiteList, newEndpointMeta)
	}

	return thisVersionInfo, nil
}

func (s *SwaggerAST) InsertIntoAPIDefinitionAsVersion(thisVersion tykcommon.VersionInfo, thisDefinition *tykcommon.APIDefinition, versionName string) error {
	thisDefinition.VersionData.NotVersioned = false
	thisDefinition.VersionData.Versions[versionName] = thisVersion
	return nil
}

// Comand mode stuff

func handleSwaggerMode(arguments map[string]interface{}) {
	doCreate := arguments["--create-api"]
	inputFile := arguments["--import-swagger"]
	if doCreate == true {
		upstreamVal := arguments["--upstream-target"]
		orgId := arguments["--org-id"]
		if upstreamVal != nil && orgId != nil {
			// Create the API with the blueprint
			s, err := swaggerLoadFile(inputFile.(string))
			if err != nil {
				log.Error("File load error: ", err)
				return
			}

			def, dErr := createDefFromSwagger(s, orgId.(string), upstreamVal.(string), arguments["--as-mock"].(bool))
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

		s, err := swaggerLoadFile(inputFile.(string))
		if err != nil {
			log.Error("File load error: ", err)
			return
		}

		versionData, err := s.ConvertIntoApiVersion(arguments["--as-mock"].(bool))
		if err != nil {
			log.Error("Conversion into API Def failed: ", err)
		}

		insertErr := s.InsertIntoAPIDefinitionAsVersion(versionData, &thisDefFromFile, versionName.(string))
		if insertErr != nil {
			log.Error("Insertion failed: ", insertErr)
			return
		}

		printDef(&thisDefFromFile)

	}
}

func createDefFromSwagger(s *SwaggerAST, orgId, upstreamURL string, as_mock bool) (*tykcommon.APIDefinition, error) {
	thisAD := tykcommon.APIDefinition{}
	thisAD.Name = s.Info.Title
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

	if as_mock {
		log.Warning("Mocks not supported for Swagger definitions, ignoring option")
	}
	versionData, err := s.ConvertIntoApiVersion(false)
	if err != nil {
		log.Error("Conversion into API Def failed: ", err)
	}

	s.InsertIntoAPIDefinitionAsVersion(versionData, &thisAD, strings.Trim(s.Info.Version, " "))

	return &thisAD, nil
}

func swaggerLoadFile(filePath string) (*SwaggerAST, error) {
	thisSwagger, astErr := GetImporterForSource(SwaggerSource)

	if astErr != nil {
		log.Error("Couldn't get swagger importer: ", astErr)
		return thisSwagger.(*SwaggerAST), astErr
	}

	swaggerFileData, err := ioutil.ReadFile(filePath)

	if err != nil {
		log.Error("Couldn't load swagger file: ", err)
		return thisSwagger.(*SwaggerAST), err
	}

	readErr := thisSwagger.ReadString(string(swaggerFileData))
	if readErr != nil {
		log.Error("Failed to decode object")
		return thisSwagger.(*SwaggerAST), readErr
	}

	return thisSwagger.(*SwaggerAST), nil
}
