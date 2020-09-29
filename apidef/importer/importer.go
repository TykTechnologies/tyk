package importer

import (
	"errors"
	"io"

	"github.com/TykTechnologies/tyk/v3/apidef"
	logger "github.com/TykTechnologies/tyk/v3/log"
)

var log = logger.Get()

type APIImporter interface {
	LoadFrom(io.Reader) error
	ConvertIntoApiVersion(bool) (apidef.VersionInfo, error)
	InsertIntoAPIDefinitionAsVersion(apidef.VersionInfo, *apidef.APIDefinition, string) error
	ToAPIDefinition(string, string, bool) (*apidef.APIDefinition, error)
}

type APIImporterSource string

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
