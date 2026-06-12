package mcp

import (
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/buger/jsonparser"
	"github.com/hashicorp/go-multierror"
	pkgver "github.com/hashicorp/go-version"

	tykerrors "github.com/TykTechnologies/tyk/internal/errors"
	"github.com/TykTechnologies/tyk/internal/service/gojsonschema"
	logger "github.com/TykTechnologies/tyk/log"
)

//go:embed schema/*
var schemaDir embed.FS

const (
	keyDefinitions              = "definitions"
	keyDefs                     = "$defs" // For OAS 3.1+ (JSON Schema 2020-12)
	keyProperties               = "properties"
	keyRequired                 = "required"
	mcpSchemaVersionNotFoundFmt = "schema not found for version %q"
	ExtensionTykAPIGateway      = "x-tyk-api-gateway"
	ExtensionTykMCPServer       = "x-tyk-mcp-server"
)

var (
	log = logger.Get()

	schemaOnce sync.Once

	mcpJSONSchemas map[string][]byte

	defaultVersion string
)

// GetDefinitionsKey returns the key used for definitions in the schema.
// OAS 3.0 uses "definitions", OAS 3.1+ uses "$defs" (JSON Schema 2020-12).
// Falls back to "definitions" if neither key is found.
func GetDefinitionsKey(schemaData []byte) string {
	// Try to find "$defs" first (OAS 3.1+)
	if _, _, _, err := jsonparser.Get(schemaData, keyDefs); err == nil {
		return keyDefs
	}
	// Fall back to "definitions" (OAS 3.0 or unknown)
	return keyDefinitions
}

func loadMCPSchema() error {
	load := func() error {
		// Load extension schemas.
		xTykAPIGwSchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", ExtensionTykAPIGateway))
		if err != nil {
			return fmt.Errorf("%s loading failed: %w", ExtensionTykAPIGateway, err)
		}
		xTykMCPServerSchema, err := schemaDir.ReadFile(fmt.Sprintf("schema/%s.json", ExtensionTykMCPServer))
		if err != nil {
			return fmt.Errorf("%s loading failed: %w", ExtensionTykMCPServer, err)
		}
		extensionSchemas := []struct {
			name string
			data []byte
		}{
			{name: ExtensionTykAPIGateway, data: xTykAPIGwSchema},
			{name: ExtensionTykMCPServer, data: xTykMCPServerSchema},
		}

		mcpJSONSchemas = make(map[string][]byte)
		members, err := schemaDir.ReadDir("schema")
		if err != nil {
			return err
		}

		for _, member := range members {
			if member.IsDir() {
				continue
			}

			fileName := member.Name()
			if !strings.HasSuffix(fileName, ".json") {
				continue
			}

			// Skip extension schemas (we'll inject them)
			if isMCPExtensionSchema(fileName) {
				continue
			}

			var data []byte
			data, err = schemaDir.ReadFile(filepath.Join("schema/", fileName))
			if err != nil {
				return err
			}

			// Detect which definitions key this schema uses
			defsKey := GetDefinitionsKey(data)

			for _, extSchema := range extensionSchemas {
				extensionSchemaWithoutDefs := jsonparser.Delete(extSchema.data, keyDefinitions)

				// Inject extension as property.
				data, err = jsonparser.Set(data, extensionSchemaWithoutDefs, keyProperties, extSchema.name)
				if err != nil {
					return err
				}

				// Merge extension definitions into schema.
				data, err = mergeMCPExtensionDefinitions(data, extSchema.data, defsKey)
				if err != nil {
					return err
				}
			}

			oasVersion := strings.TrimSuffix(fileName, ".json")
			mcpJSONSchemas[oasVersion] = data
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

func isMCPExtensionSchema(fileName string) bool {
	return strings.HasSuffix(fileName, fmt.Sprintf("%s.json", ExtensionTykAPIGateway)) ||
		strings.HasSuffix(fileName, fmt.Sprintf("%s.json", ExtensionTykMCPServer))
}

func mergeMCPExtensionDefinitions(data, extensionSchema []byte, defsKey string) ([]byte, error) {
	var definitions []byte
	err := jsonparser.ObjectEach(extensionSchema, func(key []byte, value []byte, _ jsonparser.ValueType, _ int) error {
		if string(key) == keyDefinitions {
			definitions = append([]byte(nil), value...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if definitions == nil {
		return data, nil
	}

	var setErr error
	err = jsonparser.ObjectEach(definitions, func(key []byte, value []byte, _ jsonparser.ValueType, _ int) error {
		data, setErr = jsonparser.Set(data, value, defsKey, string(key))
		return setErr
	})
	if err != nil {
		return nil, err
	}
	return data, nil
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

// ValidateMCPObject validates an MCP Proxy document against a particular OAS version.
// MCP Proxies are OAS-based but with stricter requirements for MCP-specific fields.
func ValidateMCPObject(documentBody []byte, oasVersion string) error {
	mcpSchema, err := GetMCPSchema(oasVersion)
	if err != nil {
		return err
	}

	return validateJSON(mcpSchema, documentBody)
}

// GetMCPSchema returns an MCP schema for a particular version.
func GetMCPSchema(version string) ([]byte, error) {
	if err := loadMCPSchema(); err != nil {
		return nil, fmt.Errorf("loadMCPSchema failed: %w", err)
	}

	if version == "" {
		return mcpJSONSchemas[defaultVersion], nil
	}

	minorVersion, err := getMinorVersion(version)
	if err != nil {
		return nil, err
	}

	mcpSchema, ok := mcpJSONSchemas[minorVersion]
	if !ok {
		return nil, fmt.Errorf(mcpSchemaVersionNotFoundFmt, version)
	}

	return mcpSchema, nil
}

func findDefaultVersion(rawVersions []string) string {
	versions := make([]*pkgver.Version, 0, len(rawVersions))
	for _, raw := range rawVersions {
		v, err := pkgver.NewVersion(raw)
		if err != nil {
			log.Errorf("failed to parse version %q: %v", raw, err)
			continue
		}
		versions = append(versions, v)
	}

	if len(versions) == 0 {
		return ""
	}

	sort.Sort(pkgver.Collection(versions))
	latestVersion := versions[len(versions)-1].String()
	latestMinor, err := getMinorVersion(latestVersion)
	if err != nil {
		log.Errorf("failed to get minor version from %q: %v", latestVersion, err)
		return ""
	}
	return latestMinor
}

func setDefaultVersion() {
	var versions []string
	for k := range mcpJSONSchemas {
		versions = append(versions, k)
	}

	latestVersion := findDefaultVersion(versions)

	// Override: Keep 3.0 as default until 3.1 implementation is stable across all products
	// TODO: Remove this override when 3.1 implementation is stable
	if latestVersion == "3.1" {
		defaultVersion = "3.0"
	} else {
		defaultVersion = latestVersion
	}
}

func getMinorVersion(version string) (string, error) {
	v, err := pkgver.NewVersion(version)
	if err != nil {
		return "", err
	}

	segments := v.Segments()
	return fmt.Sprintf("%d.%d", segments[0], segments[1]), nil
}
