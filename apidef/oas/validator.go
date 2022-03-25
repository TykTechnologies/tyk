package oas

import (
	"io/ioutil"
	"os"
	"strings"

	logger "github.com/TykTechnologies/tyk/log"
	"github.com/xeipuuv/gojsonschema"
)

var log = logger.Get()
var oasJSONSchemas map[string][]byte

func init() {
	oasJSONSchemas = make(map[string][]byte)
	baseDir := "./schema/"
	files, err := os.ReadDir(baseDir)

	if err != nil {
		log.WithError(err).Error("error while listing schema files")
		return
	}

	for _, fileInfo := range files {
		if fileInfo.IsDir() {
			continue
		}

		oasVersion := strings.TrimSuffix(fileInfo.Name(), ".json")
		file, err := os.Open(baseDir + fileInfo.Name())
		if err != nil {
			log.WithError(err).Error("error while loading oas json schema")
			continue
		}

		oasJSONSchema, err := ioutil.ReadAll(file)
		if err != nil {
			log.WithError(err).Error("error while reading schema file")
			continue
		}

		oasJSONSchemas[oasVersion] = oasJSONSchema
	}

}

func ValidateOASObject(documentBody []byte, oasVersion string) (bool, []string) {
	schemaLoader := gojsonschema.NewBytesLoader(oasJSONSchemas[oasVersion])
	documentLoader := gojsonschema.NewBytesLoader(documentBody)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		log.WithError(err).Errorln("error while validating document")
		return false, nil
	}

	if !result.Valid() {
		log.Error("OAS object validation failed, most likely malformed input")
		validationErrs := result.Errors()
		var errs = make([]string, len(validationErrs))
		for i, validationErr := range validationErrs {
			errStr := validationErr.String()
			errs[i] = errStr
		}
		return false, errs
	}

	return true, nil
}
