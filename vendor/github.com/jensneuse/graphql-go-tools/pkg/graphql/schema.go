package graphql

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
	"github.com/jensneuse/graphql-go-tools/pkg/astvalidation"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/introspection"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type TypeFields struct {
	TypeName   string
	FieldNames []string
}

type TypeFieldArguments struct {
	TypeName      string
	FieldName     string
	ArgumentNames []string
}

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

func (s *Schema) GetAllFieldArguments(skipFieldFuncs ...SkipFieldFunc) []TypeFieldArguments {
	objectTypeExtensions := make(map[string]ast.ObjectTypeExtension)
	for _, objectTypeExtension := range s.document.ObjectTypeExtensions {
		typeName, ok := s.typeNameOfObjectTypeIfHavingFields(objectTypeExtension.ObjectTypeDefinition)
		if !ok {
			continue
		}

		objectTypeExtensions[typeName] = objectTypeExtension
	}

	typeFieldArguments := make([]TypeFieldArguments, 0)
	for _, objectType := range s.document.ObjectTypeDefinitions {
		typeName, ok := s.typeNameOfObjectTypeIfHavingFields(objectType)
		if !ok {
			continue
		}

		for _, fieldRef := range objectType.FieldsDefinition.Refs {
			fieldName, skip := s.determineIfFieldWithFieldNameShouldBeSkipped(fieldRef, typeName, skipFieldFuncs...)
			if skip {
				continue
			}

			s.addTypeFieldArgsForFieldRef(fieldRef, typeName, fieldName, &typeFieldArguments)
		}

		objectTypeExt, ok := objectTypeExtensions[typeName]
		if !ok {
			continue
		}

		for _, fieldRef := range objectTypeExt.FieldsDefinition.Refs {
			fieldName, skip := s.determineIfFieldWithFieldNameShouldBeSkipped(fieldRef, typeName, skipFieldFuncs...)
			if skip {
				continue
			}

			s.addTypeFieldArgsForFieldRef(fieldRef, typeName, fieldName, &typeFieldArguments)
		}
	}

	return typeFieldArguments
}

func (s *Schema) typeNameOfObjectTypeIfHavingFields(objectType ast.ObjectTypeDefinition) (typeName string, ok bool) {
	if !objectType.HasFieldDefinitions {
		return "", false
	}

	return s.document.Input.ByteSliceString(objectType.Name), true
}

func (s *Schema) fieldNameOfFieldDefinitionIfHavingArguments(field ast.FieldDefinition, ref int) (fieldName string, ok bool) {
	if !field.HasArgumentsDefinitions {
		return "", false
	}

	return s.document.FieldDefinitionNameString(ref), true
}

func (s *Schema) determineIfFieldWithFieldNameShouldBeSkipped(ref int, typeName string, skipFieldFuncs ...SkipFieldFunc) (fieldName string, skip bool) {
	field := s.document.FieldDefinitions[ref]
	fieldName, ok := s.fieldNameOfFieldDefinitionIfHavingArguments(field, ref)
	if !ok {
		return fieldName, true
	}

	for _, skipFieldFunc := range skipFieldFuncs {
		if skipFieldFunc != nil && skipFieldFunc(typeName, fieldName, s.document) {
			skip = true
			break
		}
	}

	return fieldName, skip
}

func (s *Schema) addTypeFieldArgsForFieldRef(ref int, typeName string, fieldName string, fieldArguments *[]TypeFieldArguments) {
	currentTypeFieldArgs := TypeFieldArguments{
		TypeName:      typeName,
		FieldName:     fieldName,
		ArgumentNames: make([]string, 0),
	}

	for _, argRef := range s.document.FieldDefinitions[ref].ArgumentsDefinition.Refs {
		argName := s.document.InputValueDefinitionNameString(argRef)
		currentTypeFieldArgs.ArgumentNames = append(currentTypeFieldArgs.ArgumentNames, string(argName))
	}

	*fieldArguments = append(*fieldArguments, currentTypeFieldArgs)
}

func (s *Schema) GetAllNestedFieldChildrenFromTypeField(typeName string, fieldName string, skipFieldFuncs ...SkipFieldFunc) []TypeFields {
	fields := s.nodeFieldRefs(typeName)
	if len(fields) == 0 {
		return nil
	}
	for _, ref := range fields {
		if fieldName == s.document.FieldDefinitionNameString(ref) {
			fieldTypeName := s.document.FieldDefinitionTypeNode(ref).NameString(&s.document)
			childNodes := make([]TypeFields, 0)
			s.findNestedFieldChildren(fieldTypeName, &childNodes, skipFieldFuncs...)
			return childNodes
		}
	}

	return nil
}

func (s *Schema) findNestedFieldChildren(typeName string, childNodes *[]TypeFields, skipFieldFuncs ...SkipFieldFunc) {
	fields := s.nodeFieldRefs(typeName)
	if len(fields) == 0 {
		return
	}
	for _, ref := range fields {
		fieldName := s.document.FieldDefinitionNameString(ref)
		if len(skipFieldFuncs) > 0 {
			skip := false
			for _, skipFieldFunc := range skipFieldFuncs {
				if skipFieldFunc != nil && skipFieldFunc(typeName, fieldName, s.document) {
					skip = true
					break
				}
			}

			if skip {
				continue
			}
		}

		if added := s.putChildNode(childNodes, typeName, fieldName); !added {
			continue
		}

		fieldTypeName := s.document.FieldDefinitionTypeNode(ref).NameString(&s.document)
		s.findNestedFieldChildren(fieldTypeName, childNodes, skipFieldFuncs...)
	}
}

func (s *Schema) nodeFieldRefs(typeName string) []int {
	node, exists := s.document.Index.FirstNodeByNameStr(typeName)
	if !exists {
		return nil
	}
	var fields []int
	switch node.Kind {
	case ast.NodeKindObjectTypeDefinition:
		fields = s.document.ObjectTypeDefinitions[node.Ref].FieldsDefinition.Refs
	case ast.NodeKindInterfaceTypeDefinition:
		fields = s.document.InterfaceTypeDefinitions[node.Ref].FieldsDefinition.Refs
	default:
		return nil
	}

	return fields
}

func (s *Schema) putChildNode(nodes *[]TypeFields, typeName, fieldName string) (added bool) {
	for i := range *nodes {
		if typeName != (*nodes)[i].TypeName {
			continue
		}
		for j := range (*nodes)[i].FieldNames {
			if fieldName == (*nodes)[i].FieldNames[j] {
				return false
			}
		}
		(*nodes)[i].FieldNames = append((*nodes)[i].FieldNames, fieldName)
		return true
	}
	*nodes = append(*nodes, TypeFields{
		TypeName:   typeName,
		FieldNames: []string{fieldName},
	})
	return true
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

type SkipFieldFunc func(typeName, fieldName string, definition ast.Document) bool

func NewIsDataSourceConfigV2RootFieldSkipFunc(dataSources []plan.DataSourceConfiguration) SkipFieldFunc {
	return func(typeName, fieldName string, _ ast.Document) bool {
		for i := range dataSources {
			for j := range dataSources[i].RootNodes {
				if typeName != dataSources[i].RootNodes[j].TypeName {
					continue
				}
				for k := range dataSources[i].RootNodes[j].FieldNames {
					if fieldName == dataSources[i].RootNodes[j].FieldNames[k] {
						return true
					}
				}
			}
		}
		return false
	}
}

func NewSkipReservedNamesFunc() SkipFieldFunc {
	return func(typeName, fieldName string, _ ast.Document) bool {
		prefix := "__"
		return strings.HasPrefix(typeName, prefix) || strings.HasPrefix(fieldName, prefix)
	}
}
