package structs

import (
	"encoding/json"
	"os"
)

type Request struct {
	rootName    string
	pkgPath     string
	ignoreFiles []string
}

func Dump() (err error) {
	sts, err := Extract("Config", "config/")
	if err != nil {
		return err
	}

	return dump("schema/structs/config.json", sts)
}

func dump(filename string, data interface{}) error {
	println(filename)

	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, dataBytes, 0644) //nolint:gosec
}
