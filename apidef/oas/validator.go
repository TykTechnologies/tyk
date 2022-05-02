package oas

//go:generate go-bindata -pkg schema -nomemcopy -nometadata -ignore=(schema\/schema.gen.go|schema\/README.md) -prefix "./schema" -o schema/schema.gen.go schema/...
//go:generate gofmt -w -s schema/schema.gen.go

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/tyk/apidef/oas/schema"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-version"
	"github.com/xeipuuv/gojsonschema"
)

const (
	keyDefinitions = "definitions"
	keyProperties  = "properties"
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

	defaultVersion string
)

func init() {
	if err := loadOASSchema(); err != nil {
		log.WithError(err).Error("loadOASSchema failed!")
		return
	}

	setDefaultVersion()
}

func loadOASSchema() error {
	mu.Lock()
	defer mu.Unlock()
	xTykAPIGwSchema, err := schema.Asset(fmt.Sprintf("%s.json", ExtensionTykAPIGateway))
	if err != nil {
		return fmt.Errorf("%s loading failed: %w", ExtensionTykAPIGateway, err)
	}

	xTykAPIGwSchemaWithoutDefs := jsonparser.Delete(xTykAPIGwSchema, keyDefinitions)
	oasJsonSchemas = make(map[string][]byte)
	fileNames := schema.AssetNames()
	for _, fileName := range fileNames {
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}

		if strings.HasPrefix(fileName, ExtensionTykAPIGateway) {
			continue
		}

		var data []byte
		data, err = schema.Asset(fileName)
		if err != nil {
			return err
		}

		data, err = jsonparser.Set(data, xTykAPIGwSchemaWithoutDefs, keyProperties, ExtensionTykAPIGateway)
		if err != nil {
			return err
		}

		err = jsonparser.ObjectEach(xTykAPIGwSchema, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
			data, err = jsonparser.Set(data, value, keyDefinitions, string(key))
			return err
		}, keyDefinitions)
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
	if version == "" {
		return oasJsonSchemas[defaultVersion]
	}

	return oasJsonSchemas[version]
}

func findDefaultVersion(rawVersions []string) string {
	versions := make([]*version.Version, len(rawVersions))
	for i, raw := range rawVersions {
		v, _ := version.NewVersion(raw)
		versions[i] = v
	}

	sort.Sort(version.Collection(versions))
	return versions[len(rawVersions)-1].String()
}

func setDefaultVersion() {
	mu.Lock()
	defer mu.Unlock()
	var versions []string
	for k := range oasJsonSchemas {
		versions = append(versions, k)
	}

	defaultVersion = findDefaultVersion(versions)
}
