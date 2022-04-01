package oas

//go:generate go-bindata -pkg schema -nomemcopy -ignore=(schema\/schema.go|schema\/README.md) -prefix "./schema" -o schema/schema.go schema/...
//go:generate gofmt -w -s schema/schema.go

import (
	"errors"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef/oas/schema"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
)

var (
	log            = logger.Get()
	oasJsonSchemas map[string][]byte
	mu             sync.Mutex
	errorFormatter = func(errs []error) string {
		var result strings.Builder
		for i, err := range errs {
			result.WriteString(err.Error())
			if i < len(errs)-1 {
				result.WriteString("\n")
			}
		}

		return result.String()
	}
)

func init() {
	if err := loadOASSchema(); err != nil {
		log.WithError(err).Error("loadOASSchema failed!")
	}
}

func loadOASSchema() error {
	oasJsonSchemas = make(map[string][]byte)
	fileNames := schema.AssetNames()
	for _, fileName := range fileNames {
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}

		data, err := schema.Asset(fileName)
		if err != nil {
			return err
		}

		oasVersion := strings.TrimSuffix(fileName, ".json")
		oasJsonSchemas[oasVersion] = data
	}

	return nil
}

func ValidateOASObject(documentBody []byte, oasVersion string) error {
	schemaLoader := gojsonschema.NewBytesLoader(GetOASSchema(oasVersion))
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

func GetOASSchema(version string) []byte {
	mu.Lock()
	defer mu.Unlock()
	return oasJsonSchemas[version]
}
