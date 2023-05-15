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
	if err := write("schema/structs/config.json", "config/"); err != nil {
		return err
	}
	if err := write("schema/structs/apidef.json", "apidef/"); err != nil {
		return err
	}
	return nil
}

func write(filename string, inputPackage string) error {
	sts, err := Extract(inputPackage)
	if err != nil {
		return err
	}

	return dump(filename, sts)
}

func dump(filename string, data interface{}) error {
	println(filename)

	dataBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, dataBytes, 0644) //nolint:gosec
}
