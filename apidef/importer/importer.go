package importer

import (
	"errors"
	"io"

	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

// SW-REQ-082
type APIImporter interface {
	LoadFrom(io.Reader) error
	ConvertIntoApiVersion(bool) (apidef.VersionInfo, error)
	InsertIntoAPIDefinitionAsVersion(apidef.VersionInfo, *apidef.APIDefinition, string) error
	ToAPIDefinition(string, string, bool) (*apidef.APIDefinition, error)
}

// SW-REQ-082
type APIImporterSource string

// SW-REQ-082
func GetImporterForSource(source APIImporterSource) (APIImporter, error) {
	// Extend to add new importers
	switch source {
	case ApiaryBluePrint:
		return &BluePrintAST{}, nil
	case SwaggerSource:
		return &SwaggerAST{}, nil
	case WSDLSource:
		return &WSDLDef{}, nil
	default:
		return nil, errors.New("source not matched, failing")
	}
}
