package oas

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/buger/jsonparser"

	logger "github.com/TykTechnologies/tyk/log"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-version"
	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema/*
var schemaDir embed.FS

const (
	keyDefinitions              = "definitions"
	keyProperties               = "properties"
	oasSchemaVersionNotFoundFmt = "Schema not found for version %q"
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

	xTykAPIGwSchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", ExtensionTykAPIGateway))
	if err != nil {
		return fmt.Errorf("%s loading failed: %w", ExtensionTykAPIGateway, err)
	}

	xTykAPIGwSchemaWithoutDefs := jsonparser.Delete(xTykAPIGwSchema, keyDefinitions)
	oasJsonSchemas = make(map[string][]byte)
	members, err := schemaDir.ReadDir("schema")
	for _, member := range members {
		if member.IsDir() {
			continue
		}

		fileName := member.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}

		if strings.HasSuffix(fileName, fmt.Sprintf("%s.json", ExtensionTykAPIGateway)) {
			continue
		}

		var data []byte
		data, err = schemaDir.ReadFile(filepath.Join("schema/", fileName))
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
	oasSchema, err := GetOASSchema(oasVersion)
	if err != nil {
		return err
	}

	schemaLoader := gojsonschema.NewBytesLoader(oasSchema)
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

func GetOASSchema(reqOASVersion string) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()

	if reqOASVersion == "" {
		return oasJsonSchemas[defaultVersion], nil
	}

	minorVersion, err := getMinorVersion(reqOASVersion)
	if err != nil {
		return nil, err
	}

	oasSchema, ok := oasJsonSchemas[minorVersion]
	if !ok {
		return nil, fmt.Errorf(oasSchemaVersionNotFoundFmt, reqOASVersion)
	}

	return oasSchema, nil
}

func findDefaultVersion(rawVersions []string) string {
	versions := make([]*version.Version, len(rawVersions))
	for i, raw := range rawVersions {
		v, _ := version.NewVersion(raw)
		versions[i] = v
	}

	sort.Sort(version.Collection(versions))
	latestVersion := versions[len(rawVersions)-1].String()
	latestMinor, _ := getMinorVersion(latestVersion)
	return latestMinor
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

func getMinorVersion(reqOASVersion string) (string, error) {
	v, err := version.NewVersion(reqOASVersion)
	if err != nil {
		return "", err
	}

	segments := v.Segments()
	return fmt.Sprintf("%d.%d", segments[0], segments[1]), nil
}
