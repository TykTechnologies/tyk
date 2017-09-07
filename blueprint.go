package main

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/TykTechnologies/tyk/apidef"
)

type APIImporterSource string

const ApiaryBluePrint APIImporterSource = "blueprint"

type APIImporter interface {
	LoadFrom(io.Reader) error
	ConvertIntoApiVersion(bool) (apidef.VersionInfo, error)
	InsertIntoAPIDefinitionAsVersion(apidef.VersionInfo, *apidef.APIDefinition, string) error
}

func GetImporterForSource(source APIImporterSource) (APIImporter, error) {
	// Extend to add new importers
	switch source {
	case ApiaryBluePrint:
		return &BluePrintAST{}, nil
	case SwaggerSource:
		return &SwaggerAST{}, nil
	default:
		return nil, errors.New("source not matched, failing")
	}
}

type BluePrintAST struct {
	Version     string `json:"_version"`
	Description string `json:"description"`
	Metadata    []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"metadata"`
	Name           string `json:"name"`
	ResourceGroups []struct {
		Description string `json:"description"`
		Name        string `json:"name"`
		Resources   []struct {
			Actions []struct {
				Description string `json:"description"`
				Examples    []struct {
					Description string `json:"description"`
					Name        string `json:"name"`
					Requests    []struct {
						Body        string `json:"body"`
						Description string `json:"description"`
						Headers     []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"headers"`
						Name   string `json:"name"`
						Schema string `json:"schema"`
					} `json:"requests"`
					Responses []struct {
						Body        string `json:"body"`
						Description string `json:"description"`
						Headers     []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"headers"`
						Name   string `json:"name"`
						Schema string `json:"schema"`
					} `json:"responses"`
				} `json:"examples"`
				Method     string `json:"method"`
				Name       string `json:"name"`
				Parameters []struct {
					Default     string `json:"default"`
					Description string `json:"description"`
					Example     string `json:"example"`
					Name        string `json:"name"`
					Required    bool   `json:"required"`
					Type        string `json:"type"`
					Values      []struct {
						Value string `json:"value"`
					} `json:"values"`
				} `json:"parameters"`
			} `json:"actions"`
			Description string `json:"description"`
			Model       struct {
				Body        string `json:"body"`
				Description string `json:"description"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				Name   string `json:"name"`
				Schema string `json:"schema"`
			} `json:"model"`
			Name       string `json:"name"`
			Parameters []struct {
				Default     string `json:"default"`
				Description string `json:"description"`
				Example     string `json:"example"`
				Name        string `json:"name"`
				Required    bool   `json:"required"`
				Type        string `json:"type"`
				Values      []struct {
					Value string `json:"value"`
				} `json:"values"`
			} `json:"parameters"`
			UriTemplate string `json:"uriTemplate"`
		} `json:"resources"`
	} `json:"resourceGroups"`
}

func (b *BluePrintAST) LoadFrom(r io.Reader) error {
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		log.Error("Unmarshalling failed: ", err)
		return err
	}
	return nil
}

func (b *BluePrintAST) ConvertIntoApiVersion(asMock bool) (apidef.VersionInfo, error) {
	versionInfo := apidef.VersionInfo{}
	versionInfo.UseExtendedPaths = true
	versionInfo.Name = b.Name

	if len(b.ResourceGroups) < 1 {
		return versionInfo, errors.New("There are no resource groups defined in this blueprint, are you sure it is correctly formatted?")
	}

	for _, resourceGroup := range b.ResourceGroups {
		if len(resourceGroup.Resources) < 1 {
			return versionInfo, errors.New("no resourcs defined in the resource group")
		}

		for _, resource := range resourceGroup.Resources {
			newMetaData := apidef.EndPointMeta{}
			newMetaData.Path = resource.UriTemplate
			newMetaData.MethodActions = make(map[string]apidef.EndpointMethodMeta)

			for _, action := range resource.Actions {
				if len(action.Examples) == 0 || len(action.Examples[0].Responses) == 0 {
					continue
				}
				endPointMethodMeta := apidef.EndpointMethodMeta{}
				code, err := strconv.Atoi(action.Examples[0].Responses[0].Name)
				if err != nil {
					log.Warning("Could not genrate response code form Name field, using 200")
					code = 200
				}
				endPointMethodMeta.Code = code

				if asMock {
					endPointMethodMeta.Action = apidef.Reply
				} else {
					endPointMethodMeta.Action = apidef.NoAction
				}

				for _, h := range action.Examples[0].Responses[0].Headers {
					endPointMethodMeta.Headers = make(map[string]string)
					endPointMethodMeta.Headers[h.Name] = h.Value
				}
				endPointMethodMeta.Data = action.Examples[0].Responses[0].Body
				newMetaData.MethodActions[action.Method] = endPointMethodMeta
			}

			// Add it to the version
			versionInfo.ExtendedPaths.WhiteList = make([]apidef.EndPointMeta, 0)
			versionInfo.ExtendedPaths.WhiteList = append(versionInfo.ExtendedPaths.WhiteList, newMetaData)
		}

	}

	return versionInfo, nil
}

func (b *BluePrintAST) InsertIntoAPIDefinitionAsVersion(version apidef.VersionInfo, def *apidef.APIDefinition, versionName string) error {
	def.VersionData.NotVersioned = false
	def.VersionData.Versions[versionName] = version
	return nil
}
