// Package astimport can be used to import Nodes manually into an AST.
//
// This is useful when an AST should be created manually.
package astimport

import (
	"fmt"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

// Importer imports Nodes into an existing AST.
// Always use NewImporter() to create a new Importer.
type Importer struct {
}

func (i *Importer) ImportType(ref int, from, to *ast.Document) int {

	astType := ast.Type{
		TypeKind: from.Types[ref].TypeKind,
		OfType:   -1,
	}

	if astType.TypeKind == ast.TypeKindNamed {
		astType.Name = to.Input.AppendInputBytes(from.TypeNameBytes(ref))
	}

	if from.Types[ref].OfType != -1 {
		astType.OfType = i.ImportType(from.Types[ref].OfType, from, to)
	}

	to.Types = append(to.Types, astType)
	return len(to.Types) - 1
}

func (i *Importer) ImportValue(fromValue ast.Value, from, to *ast.Document) (value ast.Value) {
	value.Kind = fromValue.Kind

	switch fromValue.Kind {
	case ast.ValueKindFloat:
		value.Ref = to.ImportFloatValue(
			from.FloatValueRaw(fromValue.Ref),
			from.FloatValueIsNegative(fromValue.Ref))

	case ast.ValueKindInteger:
		value.Ref = to.ImportIntValue(
			from.IntValueRaw(fromValue.Ref),
			from.IntValueIsNegative(fromValue.Ref))

	case ast.ValueKindBoolean:
		value.Ref = fromValue.Ref

	case ast.ValueKindString:
		value.Ref = to.ImportStringValue(
			from.StringValueContentBytes(fromValue.Ref),
			from.StringValueIsBlockString(fromValue.Ref))

	case ast.ValueKindNull:
		// empty case

	case ast.ValueKindEnum:
		value.Ref = to.ImportEnumValue(from.EnumValueNameBytes(fromValue.Ref))

	case ast.ValueKindVariable:
		value.Ref = to.ImportVariableValue(from.VariableValueNameBytes(fromValue.Ref))

	case ast.ValueKindList:
		value.Ref = to.ImportListValue(i.ImportListValues(fromValue.Ref, from, to))

	case ast.ValueKindObject:
		value.Ref = to.ImportObjectValue(i.ImportObjectFields(fromValue.Ref, from, to))

	default:
		value.Kind = ast.ValueKindUnknown
		fmt.Printf("astimport.Importer.ImportValue: not implemented for ValueKind: %s\n", fromValue.Kind)
	}
	return
}

func (i *Importer) ImportObjectFields(ref int, from, to *ast.Document) (refs []int) {
	objValue := from.ObjectValues[ref]

	for _, fieldRef := range objValue.Refs {
		objectField := from.ObjectFields[fieldRef]

		refs = append(refs, to.ImportObjectField(
			from.ObjectFieldNameBytes(fieldRef),
			i.ImportValue(objectField.Value, from, to)))
	}
	return
}

func (i *Importer) ImportListValues(ref int, from, to *ast.Document) (refs []int) {
	listValue := from.ListValues[ref]

	for _, valueRef := range listValue.Refs {
		value := i.ImportValue(from.Values[valueRef], from, to)
		refs = append(refs, to.AddValue(value))
	}
	return
}

func (i *Importer) ImportArgument(ref int, from, to *ast.Document) int {
	arg := ast.Argument{
		Name:  to.Input.AppendInputBytes(from.ArgumentNameBytes(ref)),
		Value: i.ImportValue(from.ArgumentValue(ref), from, to),
	}
	to.Arguments = append(to.Arguments, arg)
	return len(to.Arguments) - 1
}

func (i *Importer) ImportArguments(refs []int, from, to *ast.Document) []int {
	args := make([]int, len(refs))
	for j, k := range refs {
		args[j] = i.ImportArgument(k, from, to)
	}
	return args
}

func (i *Importer) ImportVariableDefinition(ref int, from, to *ast.Document) int {

	variableDefinition := ast.VariableDefinition{
		VariableValue: i.ImportValue(from.VariableDefinitions[ref].VariableValue, from, to),
		Type:          i.ImportType(from.VariableDefinitions[ref].Type, from, to),
		DefaultValue: ast.DefaultValue{
			IsDefined: from.VariableDefinitions[ref].DefaultValue.IsDefined,
		},
		// HasDirectives: false, //TODO: implement import directives
		// Directives:    ast.DirectiveList{},
	}

	if from.VariableDefinitions[ref].DefaultValue.IsDefined {
		variableDefinition.DefaultValue.Value = i.ImportValue(from.VariableDefinitions[ref].DefaultValue.Value, from, to)
	}

	to.VariableDefinitions = append(to.VariableDefinitions, variableDefinition)
	return len(to.VariableDefinitions) - 1
}

func (i *Importer) ImportVariableDefinitions(refs []int, from, to *ast.Document) []int {
	definitions := make([]int, len(refs))
	for j, k := range refs {
		definitions[j] = i.ImportVariableDefinition(k, from, to)
	}
	return definitions
}

func (i *Importer) ImportField(ref int, from, to *ast.Document) int {
	field := ast.Field{
		Alias: ast.Alias{
			IsDefined: from.FieldAliasIsDefined(ref),
		},
		Name:         to.Input.AppendInputBytes(from.FieldNameBytes(ref)),
		HasArguments: from.FieldHasArguments(ref),
		// HasDirectives: from.FieldHasDirectives(ref), // HasDirectives: false, //TODO: implement import directives
		SelectionSet:  -1,
		HasSelections: false,
	}
	if field.Alias.IsDefined {
		field.Alias.Name = to.Input.AppendInputBytes(from.FieldAliasBytes(ref))
	}
	if field.HasArguments {
		field.Arguments.Refs = i.ImportArguments(from.FieldArguments(ref), from, to)
	}
	to.Fields = append(to.Fields, field)
	return len(to.Fields) - 1
}
