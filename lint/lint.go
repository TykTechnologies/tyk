package lint

import (
	"encoding/json"
	"os"

	schema "github.com/xeipuuv/gojsonschema"

	"github.com/TykTechnologies/tyk/config"
)

// Run will lint the configuration file. It will return the path to the
// config file that was checked, a list of warnings and an error, if any
// happened.
func Run(paths []string) (string, []string, error) {
	var conf config.Config
	if err := config.Load(paths, &conf); err != nil {
		return "", nil, err
	}
	schemaLoader := schema.NewBytesLoader([]byte(confSchema))

	var orig map[string]interface{}
	f, err := os.Open(conf.OriginalPath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&orig); err != nil {
		return "", nil, err
	}
	if v, ok := orig["Monitor"]; ok {
		// As the old confs wrongly capitalized this key. Would
		// be fixed by WriteConf below, but we want the JSON
		// schema to not flag this error.
		orig["monitor"] = v
		delete(orig, "Monitor")
	}

	fileLoader := schema.NewGoLoader(orig)
	result, err := schema.Validate(schemaLoader, fileLoader)
	if err != nil {
		return "", nil, err
	}

	// ensure it's well formatted and the keys are all lowercase
	if err := config.WriteConf(conf.OriginalPath, &conf); err != nil {
		return "", nil, err
	}

	return conf.OriginalPath, resultWarns(result), nil
}

func resultWarns(result *schema.Result) []string {
	warns := result.Errors()
	strs := make([]string, len(warns))
	for i, warn := range warns {
		strs[i] = warn.String()
	}
	return strs
}
