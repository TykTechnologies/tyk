package graphql

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
	"github.com/jensneuse/graphql-go-tools/pkg/astvalidation"
	"github.com/jensneuse/graphql-go-tools/pkg/introspection"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
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

func ValidateSchemaString(schema string) (result ValidationResult, err error) {
	parsedSchema, err := NewSchemaFromString(schema)
	if err != nil {
		return ValidationResult{
			Valid: false,
			Errors: SchemaValidationErrors{
				SchemaValidationError{Message: err.Error()},
			},
		}, nil
	}

	return parsedSchema.Validate()
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

func (s *Schema) Validate() (result ValidationResult, err error) {
	var report operationreport.Report
	var isValid bool

	validator := astvalidation.DefaultDefinitionValidator()
	validationState := validator.Validate(&s.document, &report)
	if validationState == astvalidation.Valid {
		isValid = true
	}

	return ValidationResult{
		Valid:  isValid,
		Errors: schemaValidationErrorsFromOperationReport(report),
	}, nil
}

func (s *Schema) IntrospectionResponse(out io.Writer) error {
	var (
		introspectionData = struct {
			Data introspection.Data `json:"data"`
		}{}
		report operationreport.Report
	)
	gen := introspection.NewGenerator()
	gen.Generate(&s.document, &report, &introspectionData.Data)
	if report.HasErrors() {
		return report
	}
	return json.NewEncoder(out).Encode(introspectionData)
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

func SchemaIntrospection(schema *Schema) (*ExecutionResult, error) {
	var buf bytes.Buffer
	err := schema.IntrospectionResponse(&buf)
	return &ExecutionResult{&buf}, err
}
