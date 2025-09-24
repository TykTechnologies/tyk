package oas

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/buger/jsonparser"
	"github.com/hashicorp/go-multierror"
	pkgver "github.com/hashicorp/go-version"
)

//go:embed schema/*
var schemaDir embed.FS

const (
	keyDefinitions              = "definitions"
	keyProperties               = "properties"
	keyRequired                 = "required"
	keyAnyOf                    = "anyOf"
	oasSchemaVersionNotFoundFmt = "Schema not found for version %q"
)

var (
	log = logger.Get()

	schemaOnce sync.Once

	oasJSONSchemas map[string][]byte

	defaultVersion string
)

func loadOASSchema() error {
	load := func() error {
		xTykAPIGwSchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", ExtensionTykAPIGateway))
		if err != nil {
			return fmt.Errorf("%s loading failed: %w", ExtensionTykAPIGateway, err)
		}

		xTykAPIGwSchemaWithoutDefs := jsonparser.Delete(xTykAPIGwSchema, keyDefinitions)

		oasJSONSchemas = make(map[string][]byte)
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
			if strings.HasSuffix(fileName, fmt.Sprintf("%s.strict.json", ExtensionTykAPIGateway)) {
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
			oasJSONSchemas[oasVersion] = data
		}

		setDefaultVersion()

		return nil
	}

	var err error
	schemaOnce.Do(func() {
		err = load()
	})
	return err
}

func validateJSON(schema, document []byte) error {
	schemaLoader := gojsonschema.NewBytesLoader(schema)
	documentLoader := gojsonschema.NewBytesLoader(document)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}

	combinedErr := &multierror.Error{}
	combinedErr.ErrorFormat = tykerrors.Formatter

	validationErrs := result.Errors()
	for _, validationErr := range validationErrs {
		combinedErr = multierror.Append(combinedErr, errors.New(validationErr.String()))
	}
	return combinedErr.ErrorOrNil()

}

// ValidateOASObject validates an OAS document against a particular OAS version.
func ValidateOASObject(documentBody []byte, oasVersion string) error {
	oasSchema, err := GetOASSchema(oasVersion)
	if err != nil {
		return err
	}

	return validateJSON(oasSchema, documentBody)
}

// ValidateOASTemplate checks a Tyk OAS API template for necessary fields,
// acknowledging that some standard Tyk OAS API fields are optional in templates.
func ValidateOASTemplate(documentBody []byte, oasVersion string) error {
	oasSchema, err := GetOASSchema(oasVersion)
	if err != nil {
		return err
	}

	oasSchema = jsonparser.Delete(oasSchema, keyProperties, ExtensionTykAPIGateway, keyRequired)

	definitions, _, _, err := jsonparser.Get(oasSchema, keyDefinitions)
	if err != nil {
		return err
	}

	unsetReqFieldsPaths := []string{
		"X-Tyk-Info",
		"X-Tyk-State",
		"X-Tyk-Server",
		"X-Tyk-ListenPath",
		"X-Tyk-Upstream",
	}

	for _, path := range unsetReqFieldsPaths {
		definitions = jsonparser.Delete(definitions, path, keyRequired)
	}

	unsetAnyOfFieldsPaths := []string{
		"X-Tyk-Upstream",
	}

	for _, path := range unsetAnyOfFieldsPaths {
		definitions = jsonparser.Delete(definitions, path, keyAnyOf)
	}

	oasSchema, err = jsonparser.Set(oasSchema, definitions, keyDefinitions)
	if err != nil {
		return err
	}

	return validateJSON(oasSchema, documentBody)
}

// GetOASSchema returns an oas schema for a particular version.
func GetOASSchema(version string) ([]byte, error) {
	if err := loadOASSchema(); err != nil {
		return nil, fmt.Errorf("loadOASSchema failed: %w", err)
	}

	if version == "" {
		return oasJSONSchemas[defaultVersion], nil
	}

	minorVersion, err := getMinorVersion(version)
	if err != nil {
		return nil, err
	}

	oasSchema, ok := oasJSONSchemas[minorVersion]
	if !ok {
		return nil, fmt.Errorf(oasSchemaVersionNotFoundFmt, version)
	}

	return oasSchema, nil
}

func findDefaultVersion(rawVersions []string) string {
	versions := make([]*pkgver.Version, len(rawVersions))
	for i, raw := range rawVersions {
		v, _ := pkgver.NewVersion(raw)
		versions[i] = v
	}

	sort.Sort(pkgver.Collection(versions))
	latestVersion := versions[len(rawVersions)-1].String()
	latestMinor, _ := getMinorVersion(latestVersion)
	return latestMinor
}

func setDefaultVersion() {
	var versions []string
	for k := range oasJSONSchemas {
		versions = append(versions, k)
	}

	defaultVersion = findDefaultVersion(versions)
}

func getMinorVersion(version string) (string, error) {
	v, err := pkgver.NewVersion(version)
	if err != nil {
		return "", err
	}

	segments := v.Segments()
	return fmt.Sprintf("%d.%d", segments[0], segments[1]), nil
}
