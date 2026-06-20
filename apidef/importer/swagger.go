package importer

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/tyk/internal/uuid"
)

// SW-REQ-083
const SwaggerSource APIImporterSource = "swagger"

// SW-REQ-083
type DefinitionObjectFormatAST struct {
	Format string `json:"format"`
	Type   string `json:"type"`
}

// SW-REQ-083
type DefinitionObjectAST struct {
	Type       string                               `json:"type"`
	Required   []string                             `json:"required"`
	Properties map[string]DefinitionObjectFormatAST `json:"properties"`
}

// SW-REQ-083
type ResponseCodeObjectAST struct {
	Description string `json:"description"`
	Schema      struct {
		Items map[string]interface{} `json:"items"`
		Type  string                 `json:"type"`
	} `json:"schema"`
}

// SW-REQ-083
type PathMethodObject struct {
	Description string                           `json:"description"`
	OperationID string                           `json:"operationId"`
	Responses   map[string]ResponseCodeObjectAST `json:"responses"`
}

// SW-REQ-083
type PathItemObject struct {
	Get     PathMethodObject `json:"get"`
	Put     PathMethodObject `json:"put"`
	Post    PathMethodObject `json:"post"`
	Patch   PathMethodObject `json:"patch"`
	Options PathMethodObject `json:"options"`
	Delete  PathMethodObject `json:"delete"`
	Head    PathMethodObject `json:"head"`
}

// SW-REQ-083
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

// SW-REQ-083
func (s *SwaggerAST) LoadFrom(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}

// SW-REQ-083
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
	pathNames := make([]string, 0, len(s.Paths))
	for pathName := range s.Paths {
		pathNames = append(pathNames, pathName)
	}
	sort.Strings(pathNames)

	for _, pathName := range pathNames {
		pathSpec := s.Paths[pathName]
		whitelistMeta := apidef.EndPointMeta{
			Path:          pathName,
			MethodActions: map[string]apidef.EndpointMethodMeta{},
		}

		trackMeta := apidef.TrackEndpointMeta{
			Path: pathName,
		}

		// We just want the paths here, no mocks
		methods := []struct {
			name   string
			method PathMethodObject
		}{
			{name: "DELETE", method: pathSpec.Delete},
			{name: "GET", method: pathSpec.Get},
			{name: "HEAD", method: pathSpec.Head},
			{name: "OPTIONS", method: pathSpec.Options},
			{name: "PATCH", method: pathSpec.Patch},
			{name: "POST", method: pathSpec.Post},
			{name: "PUT", method: pathSpec.Put},
		}

		for _, entry := range methods {
			methodName := entry.name
			m := entry.method
			// skip methods that are not defined
			if len(m.Responses) == 0 && m.Description == "" && m.OperationID == "" {
				continue
			}

			whitelistMeta.MethodActions[methodName] = apidef.EndpointMethodMeta{
				Action: apidef.NoAction,
				Code:   http.StatusOK,
			}

			trackMeta.Method = methodName
			versionInfo.ExtendedPaths.TrackEndpoints = append(versionInfo.ExtendedPaths.TrackEndpoints, trackMeta)
		}

		if len(whitelistMeta.MethodActions) > 0 {
			versionInfo.ExtendedPaths.WhiteList = append(versionInfo.ExtendedPaths.WhiteList, whitelistMeta)
		}
	}

	return versionInfo, nil
}

// SW-REQ-083
func (s *SwaggerAST) InsertIntoAPIDefinitionAsVersion(version apidef.VersionInfo, def *apidef.APIDefinition, versionName string) error {
	def.VersionData.NotVersioned = false
	def.VersionData.Versions[versionName] = version
	return nil
}

// SW-REQ-083
func (s *SwaggerAST) ToAPIDefinition(orgId, upstreamURL string, as_mock bool) (*apidef.APIDefinition, error) {
	ad := apidef.APIDefinition{
		Name:             s.Info.Title,
		Active:           true,
		UseKeylessAccess: true,
		APIID:            uuid.NewHex(),
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
