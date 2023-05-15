package defaults

import (
	"encoding/json"
	"os"

	"github.com/TykTechnologies/tyk/config"
)

func Dump() (err error) {
	// The Gateway Config Defaults
	err = dump("schema/structs/config-default.json", config.Default)
	if err != nil {
		return err
	}
	return nil
}

func dump(filename string, data interface{}) error {
	println(filename)

	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	cleanedBytes, err := SanitizeJSON(dataBytes)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, cleanedBytes, 0644) //nolint:gosec
}
