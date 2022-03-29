package oas

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/pkg/errors"

	logger "github.com/TykTechnologies/tyk/log"
	"github.com/xeipuuv/gojsonschema"
)

var log = logger.Get()
var oasJSONSchemas map[string][]byte
var errorFormatter = func(errs []error) string {
	var result strings.Builder
	for i, err := range errs {
		result.WriteString(err.Error())
		if i < len(errs)-1 {
			result.WriteString("\n")
		}
	}
	return result.String()
}

func init() {
	if err := loadOASSchema(); err != nil {
		log.WithError(err).Error("loadOASSchema failed!")
	}

}

func loadOASSchema() error {
	oasJSONSchemas = make(map[string][]byte)
	baseDir := "./schema/"
	files, err := os.ReadDir(baseDir)

	if err != nil {
		return errors.Wrap(err, "error while listing schema files")
	}
	combinedErr := &multierror.Error{}
	combinedErr.ErrorFormat = errorFormatter

	for _, fileInfo := range files {

		if fileInfo.IsDir() {
			continue
		}

		oasVersion := strings.TrimSuffix(fileInfo.Name(), ".json")
		file, err := os.Open(baseDir + fileInfo.Name())
		if err != nil {
			combinedErr = multierror.Append(combinedErr, errors.Wrapf(err, "error while loading oas json schema %s", fileInfo.Name()))
			continue
		}

		oasJSONSchema, err := ioutil.ReadAll(file)
		if err != nil {
			combinedErr = multierror.Append(combinedErr, errors.Wrapf(err, "error while reading file %s", fileInfo.Name()))
			continue
		}

		oasJSONSchemas[oasVersion] = oasJSONSchema
	}

	return combinedErr.ErrorOrNil()
}

func ValidateOASObject(documentBody []byte, oasVersion string) error {
	schemaLoader := gojsonschema.NewBytesLoader(oasJSONSchemas[oasVersion])
	documentLoader := gojsonschema.NewBytesLoader(documentBody)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		return err
	}

	if !result.Valid() {
		combinedErr := &multierror.Error{}
		combinedErr.ErrorFormat = errorFormatter

		validationErrs := result.Errors()
		for _, validationErr := range validationErrs {
			combinedErr = multierror.Append(combinedErr, errors.New(validationErr.String()))
		}
		return combinedErr.ErrorOrNil()
	}

	return nil
}
