package importer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/apidef"
)

const SwaggerSource APIImporterSource = "swagger"

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

func (s *SwaggerAST) LoadFrom(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}

func (s *SwaggerAST) ConvertIntoApiVersion(asMock bool) (apidef.VersionInfo, error) {
	versionInfo := apidef.VersionInfo{}

	if asMock {
		return versionInfo, errors.New("Swagger mocks not supported")
	}

	versionInfo.UseExtendedPaths = true
	versionInfo.Name = s.Info.Version

	if len(s.Paths) == 0 {
		return versionInfo, errors.New("no paths defined in swagger file")
	}
	for pathName, pathSpec := range s.Paths {
		newEndpointMeta := apidef.EndPointMeta{
			Path:          pathName,
			MethodActions: map[string]apidef.EndpointMethodMeta{},
		}

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

			newEndpointMeta.MethodActions[methodName] = apidef.EndpointMethodMeta{
				Action: apidef.NoAction,
				Code:   http.StatusOK,
			}
		}
		versionInfo.ExtendedPaths.WhiteList = append(versionInfo.ExtendedPaths.WhiteList, newEndpointMeta)
	}

	return versionInfo, nil
}

func (s *SwaggerAST) InsertIntoAPIDefinitionAsVersion(version apidef.VersionInfo, def *apidef.APIDefinition, versionName string) error {
	def.VersionData.NotVersioned = false
	def.VersionData.Versions[versionName] = version
	return nil
}

func (s *SwaggerAST) ToAPIDefinition(orgId, upstreamURL string, as_mock bool) (*apidef.APIDefinition, error) {
	ad := apidef.APIDefinition{
		Name:             s.Info.Title,
		Active:           true,
		UseKeylessAccess: true,
		APIID:            uuid.NewV4().String(),
		OrgID:            orgId,
	}
	ad.VersionDefinition.Key = "version"
	ad.VersionDefinition.Location = "header"
	ad.VersionData.Versions = make(map[string]apidef.VersionInfo)
	ad.Proxy.ListenPath = "/" + ad.APIID + "/"
	ad.Proxy.StripListenPath = true
	ad.Proxy.TargetURL = upstreamURL

	if as_mock {
		log.Warning("Mocks not supported for Swagger definitions, ignoring option")
	}
	versionData, err := s.ConvertIntoApiVersion(false)
	if err != nil {
		return nil, err
	}

	s.InsertIntoAPIDefinitionAsVersion(versionData, &ad, strings.Trim(s.Info.Version, " "))

	return &ad, nil
}
