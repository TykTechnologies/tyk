package lint

import (
	"path/filepath"

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
	var warns []string

	absPath, err := filepath.Abs(conf.OriginalPath)
	if err != nil {
		return "", nil, err
	}
	fileLoader := schema.NewReferenceLoader("file://" + absPath)
	result, err := schema.Validate(schemaLoader, fileLoader)
	if err != nil {
		return "", nil, err
	}
	// this will pick up unknown fields and other errors unavailable
	// in encoding/json
	warns = append(warns, resultWarns(result)...)

	return conf.OriginalPath, warns, nil
}

func resultWarns(result *schema.Result) []string {
	warns := result.Errors()
	strs := make([]string, len(warns))
	for i, warn := range warns {
		strs[i] = warn.String()
	}
	return strs
}
