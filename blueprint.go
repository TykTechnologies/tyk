package main

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/TykTechnologies/tykcommon"
)

type APIImporterSource string

const (
	ApiaryBluePrint APIImporterSource = "blueprint"
)

type APIImporter interface {
	ReadString(string) error
	ConvertIntoApiVersion(bool) (tykcommon.VersionInfo, error)
	InsertIntoAPIDefinitionAsVersion(tykcommon.VersionInfo, *tykcommon.APIDefinition, string) error
}

func GetImporterForSource(source APIImporterSource) (APIImporter, error) {
	// Extend to add new importers
	switch source {
	case ApiaryBluePrint:
		thisBluePrint := &BluePrintAST{}
		return thisBluePrint, nil
	case SwaggerSource:
		thisSwaggerSource := &SwaggerAST{}
		return thisSwaggerSource, nil
	default:
		return nil, errors.New("Source not matched, failing.")
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

func (b *BluePrintAST) ReadString(asJson string) error {
	marshallErr := json.Unmarshal([]byte(asJson), &b)
	if marshallErr != nil {
		log.Error("Marshalling failed: ", marshallErr)
		return errors.New("Could not unmarshal string for Bluprint AST object")
	}

	return nil
}

func (b *BluePrintAST) ConvertIntoApiVersion(asMock bool) (tykcommon.VersionInfo, error) {
	thisVersionInfo := tykcommon.VersionInfo{}
	thisVersionInfo.UseExtendedPaths = true
	thisVersionInfo.Name = b.Name

	if len(b.ResourceGroups) < 1 {
		return thisVersionInfo, errors.New("There are no resource groups defined in this blueprint, are you sure it is correctly formatted?")
	}

	for _, resourceGroup := range b.ResourceGroups {
		if len(resourceGroup.Resources) < 1 {
			return thisVersionInfo, errors.New("No resourcs defined in the resource group.")
		}

		for _, resource := range resourceGroup.Resources {
			newMetaData := tykcommon.EndPointMeta{}
			newMetaData.Path = resource.UriTemplate
			newMetaData.MethodActions = make(map[string]tykcommon.EndpointMethodMeta)

			for _, action := range resource.Actions {
				if len(action.Examples) > 0 {
					if len(action.Examples[0].Responses) > 0 {
						thisEndPointMethodMeta := tykcommon.EndpointMethodMeta{}
						code, err := strconv.Atoi(action.Examples[0].Responses[0].Name)
						if err != nil {
							log.Warning("Could not genrate response code form Name field, using 200")
							code = 200
						}
						thisEndPointMethodMeta.Code = code

						if asMock {
							thisEndPointMethodMeta.Action = tykcommon.Reply
						} else {
							thisEndPointMethodMeta.Action = tykcommon.NoAction
						}

						for _, h := range action.Examples[0].Responses[0].Headers {
							thisEndPointMethodMeta.Headers = make(map[string]string)
							thisEndPointMethodMeta.Headers[h.Name] = h.Value
						}
						thisEndPointMethodMeta.Data = action.Examples[0].Responses[0].Body
						newMetaData.MethodActions[action.Method] = thisEndPointMethodMeta
					}
				}
			}

			// Add it to the version
			thisVersionInfo.ExtendedPaths.WhiteList = make([]tykcommon.EndPointMeta, 0)
			thisVersionInfo.ExtendedPaths.WhiteList = append(thisVersionInfo.ExtendedPaths.WhiteList, newMetaData)
		}

	}

	return thisVersionInfo, nil
}

func (b *BluePrintAST) InsertIntoAPIDefinitionAsVersion(thisVersion tykcommon.VersionInfo, thisDefinition *tykcommon.APIDefinition, versionName string) error {

	thisDefinition.VersionData.NotVersioned = false
	thisDefinition.VersionData.Versions[versionName] = thisVersion
	return nil
}

func HandleImportMode() {

}
