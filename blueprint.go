package main

import (
	"github.com/lonelycode/tykcommon"
)

type APIImporter interface {
	ReadString(string) error
	ConvertIntoApiVersion() (VersionInfo, error)
	InsertIntoAPIDefinitionAsVersion(VersionInfo, tykcommon.APIDefinition, string) (tykcommon.APIDefinition, error)
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
					Required    string `json:"required"`
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
				Required    string `json:"required"`
				Type        string `json:"type"`
				Values      []struct {
					Value string `json:"value"`
				} `json:"values"`
			} `json:"parameters"`
			UriTemplate string `json:"uriTemplate"`
		} `json:"resources"`
	} `json:"resourceGroups"`
}

