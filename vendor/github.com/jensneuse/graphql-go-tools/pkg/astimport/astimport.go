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
		to.FloatValues = append(to.FloatValues, ast.FloatValue{
			Raw:      to.Input.AppendInputBytes(from.FloatValueRaw(fromValue.Ref)),
			Negative: from.FloatValueIsNegative(fromValue.Ref),
		})
		value.Ref = len(to.FloatValues) - 1
		return
	case ast.ValueKindInteger:
		to.FloatValues = append(to.FloatValues, ast.FloatValue{
			Raw:      to.Input.AppendInputBytes(from.IntValueRaw(fromValue.Ref)),
			Negative: from.IntValueIsNegative(fromValue.Ref),
		})
		value.Ref = len(to.IntValues) - 1
		return
	case ast.ValueKindBoolean:
		value.Ref = fromValue.Ref
		return
	case ast.ValueKindString:
		to.StringValues = append(to.StringValues, ast.StringValue{
			BlockString: from.StringValueIsBlockString(fromValue.Ref),
			Content:     to.Input.AppendInputBytes(from.StringValueContentBytes(fromValue.Ref)),
		})
		return
	case ast.ValueKindNull:
		return
	case ast.ValueKindEnum:
		to.EnumValues = append(to.EnumValues, ast.EnumValue{
			Name: to.Input.AppendInputBytes(from.EnumValueNameBytes(fromValue.Ref)),
		})
		value.Ref = len(to.EnumValues) - 1
		return
	case ast.ValueKindVariable:
		to.VariableValues = append(to.VariableValues, ast.VariableValue{
			Name: to.Input.AppendInputBytes(from.VariableValueNameBytes(fromValue.Ref)),
		})
		value.Ref = len(to.VariableValues) - 1
		return
	default:
		value.Kind = ast.ValueKindUnknown
		fmt.Printf("astimport.Importer.ImportValue: not implemented fro ValueKind: %s\n", fromValue.Kind)
		return
	}
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
	for j, k := range definitions {
		definitions[j] = i.ImportVariableDefinition(k, from, to)
	}
	return definitions
}
