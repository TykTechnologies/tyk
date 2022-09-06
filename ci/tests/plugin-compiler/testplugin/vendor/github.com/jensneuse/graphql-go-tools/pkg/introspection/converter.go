package introspection

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astimport"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type JsonConverter struct {
	schema *Schema
	doc    *ast.Document
	parser *astparser.Parser
}

func (j *JsonConverter) GraphQLDocument(introspectionJSON io.Reader) (*ast.Document, error) {
	var data Data
	if err := json.NewDecoder(introspectionJSON).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse inrospection json: %v", err)
	}

	j.schema = &data.Schema
	j.doc = ast.NewDocument()
	j.parser = astparser.NewParser()

	if err := j.importSchema(); err != nil {
		return nil, fmt.Errorf("failed to convert graphql schema: %v", err)
	}

	return j.doc, nil
}

func (j *JsonConverter) importSchema() error {
	j.doc.ImportSchemaDefinition(j.schema.TypeNames())

	for i := 0; i < len(j.schema.Types); i++ {
		if err := j.importFullType(j.schema.Types[i]); err != nil {
			return err
		}
	}

	for i := 0; i < len(j.schema.Directives); i++ {
		if err := j.importDirective(j.schema.Directives[i]); err != nil {
			return err
		}
	}

	return nil
}

func (j *JsonConverter) importFullType(fullType FullType) (err error) {
	switch fullType.Kind {
	case SCALAR:
		j.doc.ImportScalarTypeDefinition(fullType.Name, fullType.Description)
	case OBJECT:
		err = j.importObject(fullType)
	case ENUM:
		j.importEnum(fullType)
	case INTERFACE:
		err = j.importInterface(fullType)
	case UNION:
		err = j.importUnion(fullType)
	case INPUTOBJECT:
		err = j.importInputObject(fullType)
	}
	return
}

func (j *JsonConverter) importObject(fullType FullType) error {
	fieldRefs, err := j.importFields(fullType.Fields)
	if err != nil {
		return err
	}

	iRefs := make([]int, len(fullType.Interfaces))
	for i := 0; i < len(iRefs); i++ {
		iRefs[i] = j.importType(fullType.Interfaces[i])
	}

	j.doc.ImportObjectTypeDefinition(
		fullType.Name,
		fullType.Description,
		fieldRefs,
		iRefs)

	return nil
}

func (j *JsonConverter) importInterface(fullType FullType) error {
	fieldRefs, err := j.importFields(fullType.Fields)
	if err != nil {
		return err
	}

	j.doc.ImportInterfaceTypeDefinition(
		fullType.Name,
		fullType.Description,
		fieldRefs)

	return nil
}

func (j *JsonConverter) importDirective(directive Directive) error {
	argRefs, err := j.importInputFields(directive.Args)
	if err != nil {
		return err
	}

	j.doc.ImportDirectiveDefinition(
		directive.Name,
		directive.Description,
		argRefs,
		directive.Locations)

	return nil
}

func (j *JsonConverter) importInputObject(fullType FullType) error {
	argRefs, err := j.importInputFields(fullType.InputFields)
	if err != nil {
		return err
	}

	j.doc.ImportInputObjectTypeDefinition(
		fullType.Name,
		fullType.Description,
		argRefs)

	return nil
}

func (j *JsonConverter) importEnum(fullType FullType) {
	valueRefs := make([]int, len(fullType.EnumValues))
	for i := 0; i < len(valueRefs); i++ {
		var directiveRefs []int
		if fullType.EnumValues[i].IsDeprecated {
			directiveRefs = append(directiveRefs, j.importDeprecatedDirective(fullType.EnumValues[i].DeprecationReason))
		}

		valueRefs[i] = j.doc.ImportEnumValueDefinition(
			fullType.EnumValues[i].Name,
			fullType.EnumValues[i].Description,
			directiveRefs,
		)
	}

	j.doc.ImportEnumTypeDefinition(
		fullType.Name,
		fullType.Description,
		valueRefs)
}

func (j *JsonConverter) importUnion(fullType FullType) error {
	typeRefs := make([]int, len(fullType.PossibleTypes))
	for i := 0; i < len(typeRefs); i++ {
		typeRefs[i] = j.importType(fullType.PossibleTypes[i])
	}

	j.doc.ImportUnionTypeDefinition(
		fullType.Name,
		fullType.Description,
		typeRefs)

	return nil
}

func (j *JsonConverter) importFields(fields []Field) (refs []int, err error) {
	refs = make([]int, len(fields))
	for i := 0; i < len(refs); i++ {
		fieldRef, err := j.importField(fields[i])
		if err != nil {
			return nil, err
		}
		refs[i] = fieldRef
	}

	return
}

func (j *JsonConverter) importField(field Field) (ref int, err error) {
	typeRef := j.importType(field.Type)

	argRefs, err := j.importInputFields(field.Args)
	if err != nil {
		return -1, err
	}

	var directiveRefs []int
	if field.IsDeprecated {
		directiveRefs = append(directiveRefs, j.importDeprecatedDirective(field.DeprecationReason))
	}

	return j.doc.ImportFieldDefinition(
		field.Name, field.Description, typeRef, argRefs, directiveRefs), nil
}

func (j *JsonConverter) importInputFields(fields []InputValue) (refs []int, err error) {
	refs = make([]int, len(fields))
	for i := 0; i < len(refs); i++ {
		argRef, err := j.importInputField(fields[i])
		if err != nil {
			return nil, err
		}
		refs[i] = argRef
	}
	return
}

func (j *JsonConverter) importInputField(field InputValue) (ref int, err error) {
	typeRef := j.importType(field.Type)

	defaultValue, err := j.importDefaultValue(field.DefaultValue)
	if err != nil {
		return -1, err
	}

	return j.doc.ImportInputValueDefinition(
		field.Name, field.Description, typeRef, defaultValue), nil
}

func (j *JsonConverter) importType(typeRef TypeRef) (ref int) {
	switch typeRef.Kind {
	case LIST:
		listType := ast.Type{
			TypeKind: ast.TypeKindList,
			OfType:   j.importType(*typeRef.OfType),
		}
		return j.doc.AddType(listType)
	case NONNULL:
		nonNullType := ast.Type{
			TypeKind: ast.TypeKindNonNull,
			OfType:   j.importType(*typeRef.OfType),
		}
		return j.doc.AddType(nonNullType)
	}

	return j.doc.AddNamedType([]byte(*typeRef.Name))
}

func (j *JsonConverter) importDefaultValue(defaultValue *string) (out ast.DefaultValue, err error) {
	if defaultValue == nil {
		return
	}

	from := ast.NewDocument()
	from.Input.AppendInputString(*defaultValue)

	report := &operationreport.Report{}

	j.parser.PrepareImport(from, report)
	value := j.parser.ParseValue()

	if report.HasErrors() {
		err = report
		return
	}

	importer := &astimport.Importer{}
	return ast.DefaultValue{
		IsDefined: true,
		Value:     importer.ImportValue(value, from, j.doc),
	}, nil
}

func (j *JsonConverter) importDeprecatedDirective(reason *string) (ref int) {
	var args []int
	if reason != nil {
		valueRef := j.doc.ImportStringValue([]byte(*reason), strings.Contains(*reason, "\n"))
		value := ast.Value{
			Kind: ast.ValueKindString,
			Ref:  valueRef,
		}
		j.doc.AddValue(value)
		args = append(args, j.doc.ImportArgument(DeprecationReasonArgName, value))
	}

	return j.doc.ImportDirective(DeprecatedDirectiveName, args)
}
