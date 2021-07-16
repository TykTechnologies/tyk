package wasm

import (
	"path/filepath"

	"github.com/TykTechnologies/tyk/apidef"
)

type InstanceConfig struct {
	ProgramName        string
	Arguments          []string
	Environments       map[string]string
	PreopenDirectories []string
	MapDirectories     map[string]string
	InheritStdin       bool
	CaptureStdout      bool
	InheritStdout      bool
	CaptureStderr      bool
	InheritStderr      bool
}

type Config struct {
	Name     string
	Module   string
	Instance InstanceConfig
	Plugin   map[string]interface{}
}

func ConfigFromApidef(a *apidef.MiddlewareDefinition) *Config {
	return &Config{
		Name:   a.Name,
		Module: a.Path,
		Instance: InstanceConfig{
			ProgramName: filepath.Base(a.Path),
		},
		Plugin: map[string]interface{}{},
	}
}
