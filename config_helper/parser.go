package config_helper

import (
	"fmt"
	"strings"

	"github.com/fatih/structs"
)

func (h *ConfigHelper) ParseEnvs() []string {
	envs := []string{}
	envVars := h.envs
	if len(envs) == 0 {
		envVars = parseEnvs(h.config)
	}
	for _, env := range envVars {
		envs = append(envs, h.prefix+env.String())
	}

	return envs
}

func parseEnvs(config interface{}) []EnvVars {
	envs := []EnvVars{}

	s := structs.New(config)

	for _, field := range s.Fields() {
		if field.IsExported() {
			newEnv := EnvVars{}
			newEnv.setKey(field)

			if structs.IsStruct(field.Value()) {
				envsInner := parseEnvs(field.Value())

				for i := range envsInner {
					envsInner[i].Key = newEnv.Key + "_" + envsInner[i].Key
				}

				envs = append(envs, envsInner...)
			} else {
				newEnv.setValue(field)
				envs = append(envs, newEnv)
			}
		}
	}
	return envs
}

type EnvVars struct {
	Key   string
	Value string
}

func (ev EnvVars) String() string {
	return ev.Key + ":" + ev.Value
}

func (ev *EnvVars) setKey(field *structs.Field) {
	key := field.Name()
	jsonTag := field.Tag("json")
	if jsonTag != "" && jsonTag != "-" {
		jsonTag = strings.Replace(jsonTag, ",omitempty", "", -1)
		key = jsonTag
	}

	key = strings.Replace(key, "_", "", -1)
	key = strings.ToUpper(key)
	ev.Key = key
}

func (ev *EnvVars) setValue(field *structs.Field) {
	ev.Value = fmt.Sprint(field.Value())
}
