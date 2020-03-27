package graphql

import (
	"io"
	"io/ioutil"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
)

type Schema struct {
	document ast.Document
}

func NewSchemaFromReader(reader io.Reader) (*Schema, error) {
	schemaContent, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return createSchema(schemaContent)
}

func NewSchemaFromString(schema string) (*Schema, error) {
	schemaContent := []byte(schema)

	return createSchema(schemaContent)
}

func (s *Schema) Document() []byte {
	return s.document.Input.RawBytes
}

func (s *Schema) Validate() (valid bool, errors SchemaValidationErrors) {
	// TODO: Needs to be implemented in the core of the library
	return true, nil
}

func createSchema(schemaContent []byte) (*Schema, error) {
	document, report := astparser.ParseGraphqlDocumentBytes(schemaContent)
	if report.HasErrors() {
		return nil, report
	}

	return &Schema{
		document: document,
	}, nil
}
