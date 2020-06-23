package graphql

import (
	"io"
	"io/ioutil"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
)

type Schema struct {
	rawInput []byte
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
	return s.rawInput
}

func (s *Schema) HasQueryType() bool {
	return len(s.document.Index.QueryTypeName) > 0
}

func (s *Schema) QueryTypeName() string {
	if !s.HasQueryType() {
		return ""
	}

	return string(s.document.Index.QueryTypeName)
}

func (s *Schema) HasMutationType() bool {
	return len(s.document.Index.MutationTypeName) > 0
}

func (s *Schema) MutationTypeName() string {
	if !s.HasMutationType() {
		return ""
	}

	return string(s.document.Index.MutationTypeName)
}

func (s *Schema) HasSubscriptionType() bool {
	return len(s.document.Index.SubscriptionTypeName) > 0
}

func (s *Schema) SubscriptionTypeName() string {
	if !s.HasSubscriptionType() {
		return ""
	}

	return string(s.document.Index.SubscriptionTypeName)
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

	err := asttransform.MergeDefinitionWithBaseSchema(&document)
	if err != nil {
		return nil, err
	}

	return &Schema{
		rawInput: schemaContent,
		document: document,
	}, nil
}
