package streams

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef/oas"

	"github.com/buger/jsonparser"
	"github.com/hashicorp/go-multierror"
	pkgver "github.com/hashicorp/go-version"
	"github.com/xeipuuv/gojsonschema"

	"github.com/TykTechnologies/tyk/apidef/streams/bento"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
)

//go:embed schema/*
var schemaDir embed.FS

const (
	keyStreams                  = "streams"
	keyDefinitions              = "definitions"
	keyProperties               = "properties"
	keyRequired                 = "required"
	oasSchemaVersionNotFoundFmt = "schema not found for version %q"
)

var (
	schemaOnce sync.Once

	oasJSONSchemas map[string][]byte

	bentoValidators map[bento.ValidatorKind]bento.ConfigValidator

	defaultVersion string
)

func loadSchemas() error {
	loadOAS := func() error {
		xTykStreamingSchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", oas.ExtensionTykStreaming))
		if err != nil {
			return fmt.Errorf("%s loading failed: %w", oas.ExtensionTykStreaming, err)
		}
		xTykStreamingSchemaWithoutDefs := jsonparser.Delete(xTykStreamingSchema, keyDefinitions)

		xTykApiGatewaySchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", oas.ExtensionTykAPIGateway))
		if err != nil {
			return fmt.Errorf("%s loading failed: %w", oas.ExtensionTykAPIGateway, err)
		}
		xTykApiGatewaySchemaWithoutDefs := jsonparser.Delete(xTykApiGatewaySchema, keyDefinitions)

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

			if strings.HasSuffix(fileName, fmt.Sprintf("%s.json", oas.ExtensionTykStreaming)) {
				continue
			}

			if strings.HasSuffix(fileName, fmt.Sprintf("%s.json", oas.ExtensionTykAPIGateway)) {
				continue
			}

			var data []byte
			data, err = schemaDir.ReadFile(filepath.Join("schema/", fileName))
			if err != nil {
				return err
			}

			data, err = jsonparser.Set(data, xTykStreamingSchemaWithoutDefs, keyProperties, oas.ExtensionTykStreaming)
			if err != nil {
				return err
			}

			data, err = jsonparser.Set(data, xTykApiGatewaySchemaWithoutDefs, keyProperties, oas.ExtensionTykAPIGateway)
			if err != nil {
				return err
			}

			err = jsonparser.ObjectEach(xTykStreamingSchema, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
				data, err = jsonparser.Set(data, value, keyDefinitions, string(key))
				return err
			}, keyDefinitions)
			if err != nil {
				return err
			}

			err = jsonparser.ObjectEach(xTykApiGatewaySchema, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
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

	loadBento := func() error {
		bentoValidators = make(map[bento.ValidatorKind]bento.ConfigValidator)
		defaultValidator, err := bento.NewDefaultConfigValidator()
		if err != nil {
			return err
		}
		bentoValidators[bento.DefaultValidator] = defaultValidator
		return nil
	}

	var err error
	schemaOnce.Do(func() {
		err = loadOAS()
		if err != nil {
			return
		}
		err = loadBento()
	})
	return err
}

func validateBentoConfiguration(document []byte, bentoValidatorKind bento.ValidatorKind) error {
	streams, _, _, err := jsonparser.Get(document, oas.ExtensionTykStreaming, keyStreams)
	if errors.Is(err, jsonparser.KeyPathNotFoundError) {
		// no streams found
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed getting streams configuration: %w", err)
	}

	bentoValidator := bentoValidators[bentoValidatorKind]
	return jsonparser.ObjectEach(streams, func(stream []byte, bentoConfiguration []byte, dataType jsonparser.ValueType, offset int) error {
		err = bentoValidator.Validate(bentoConfiguration)
		if err != nil {
			return fmt.Errorf("%s: %w", stream, err)
		}
		// Validated
		return nil
	})
}

func validateJSON(schema, document []byte, bentoValidatorKind bento.ValidatorKind) error {
	schemaLoader := gojsonschema.NewBytesLoader(schema)
	documentLoader := gojsonschema.NewBytesLoader(document)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		return err
	}

	if result.Valid() {
		// Tyk Streams OAS schema is valid.
		// Validate the Bento configuration here.
		return validateBentoConfiguration(document, bentoValidatorKind)
	}

	combinedErr := &multierror.Error{}
	combinedErr.ErrorFormat = tykerrors.Formatter

	validationErrs := result.Errors()
	for _, validationErr := range validationErrs {
		combinedErr = multierror.Append(combinedErr, errors.New(validationErr.String()))
	}
	return combinedErr.ErrorOrNil()

}

// ValidateOASObjectWithBentoConfigValidator validates a Tyk Streams document against a particular OAS version and takes an optional ConfigValidator
func ValidateOASObjectWithBentoConfigValidator(documentBody []byte, oasVersion string, bentoValidatorKind bento.ValidatorKind) error {
	oasSchema, err := GetOASSchema(oasVersion)
	if err != nil {
		return err
	}
	return validateJSON(oasSchema, documentBody, bentoValidatorKind)
}

// ValidateOASObject validates a Tyk Streams document against a particular OAS version.
func ValidateOASObject(documentBody []byte, oasVersion string) error {
	return ValidateOASObjectWithBentoConfigValidator(documentBody, oasVersion, bento.DefaultValidator)
}

// ValidateOASTemplate checks a Tyk Streams OAS API template for necessary fields,
// acknowledging that some standard Tyk OAS API fields are optional in templates.
func ValidateOASTemplate(documentBody []byte, oasVersion string) error {
	return ValidateOASTemplateWithBentoValidator(documentBody, oasVersion, bento.DefaultValidator)
}

func ValidateOASTemplateWithBentoValidator(documentBody []byte, oasVersion string, bentoValidatorKind bento.ValidatorKind) error {
	oasSchema, err := GetOASSchema(oasVersion)
	if err != nil {
		return err
	}

	oasSchema = jsonparser.Delete(oasSchema, keyProperties, oas.ExtensionTykStreaming, keyRequired)
	oasSchema = jsonparser.Delete(oasSchema, keyProperties, oas.ExtensionTykAPIGateway, keyRequired)

	definitions, _, _, err := jsonparser.Get(oasSchema, keyDefinitions)
	if err != nil {
		return err
	}

	unsetReqFieldsPaths := []string{
		"X-Tyk-Info",
		"X-Tyk-State",
		"X-Tyk-Server",
		"X-Tyk-ListenPath",
		"X-Tyk-Streams",
	}

	for _, path := range unsetReqFieldsPaths {
		definitions = jsonparser.Delete(definitions, path, keyRequired)
	}

	oasSchema, err = jsonparser.Set(oasSchema, definitions, keyDefinitions)
	if err != nil {
		return err
	}

	return validateJSON(oasSchema, documentBody, bentoValidatorKind)
}

// GetOASSchema returns an oas schema for a particular version.
func GetOASSchema(version string) ([]byte, error) {
	if err := loadSchemas(); err != nil {
		return nil, fmt.Errorf("loadSchemas failed: %w", err)
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
