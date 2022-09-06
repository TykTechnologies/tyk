package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type InputObjectTypeDefinition struct {
	Description              Description        // optional, describes the input type
	InputLiteral             position.Position  // input
	Name                     ByteSliceReference // name of the input type
	HasDirectives            bool
	Directives               DirectiveList // optional, e.g. @foo
	HasInputFieldsDefinition bool
	InputFieldsDefinition    InputValueDefinitionList // e.g. x:Float
}

func (d *Document) InputObjectTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Name)
}

func (d *Document) InputObjectTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Name))
}

func (d *Document) InputObjectTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.InputObjectTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.InputObjectTypeDefinitions[ref].Description.Content)
}

func (d *Document) InputObjectTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.InputObjectTypeDefinitionDescriptionBytes(ref))
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueString(inputObjectTypeDefinitionName, inputValueDefinitionName string) string {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindString {
		return ""
	}
	return d.StringValueContentString(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueBool(inputObjectTypeDefinitionName, inputValueDefinitionName string) bool {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindBoolean {
		return false
	}
	return bool(d.BooleanValue(defaultValue.Ref))
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueInt64(inputObjectTypeDefinitionName, inputValueDefinitionName string) int64 {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindInteger {
		return -1
	}
	return d.IntValueAsInt(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValueFloat32(inputObjectTypeDefinitionName, inputValueDefinitionName string) float32 {
	defaultValue := d.InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName)
	if defaultValue.Kind != ValueKindFloat {
		return -1
	}
	return d.FloatValueAsFloat32(defaultValue.Ref)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionDefaultValue(inputObjectTypeDefinitionName, inputValueDefinitionName string) Value {
	inputObjectTypeDefinition, exists := d.Index.FirstNodeByNameStr(inputObjectTypeDefinitionName)
	if !exists {
		return Value{}
	}
	if inputObjectTypeDefinition.Kind != NodeKindInputObjectTypeDefinition {
		return Value{}
	}
	inputValueDefinition := d.InputObjectTypeDefinitionInputValueDefinitionByName(inputObjectTypeDefinition.Ref, unsafebytes.StringToBytes(inputValueDefinitionName))
	if inputValueDefinition == -1 {
		return Value{}
	}
	return d.InputValueDefinitionDefaultValue(inputValueDefinition)
}

func (d *Document) InputObjectTypeDefinitionInputValueDefinitionByName(definition int, inputValueDefinitionName ByteSlice) int {
	for _, i := range d.InputObjectTypeDefinitions[definition].InputFieldsDefinition.Refs {
		if bytes.Equal(inputValueDefinitionName, d.InputValueDefinitionNameBytes(i)) {
			return i
		}
	}
	return -1
}

func (d *Document) AddInputObjectTypeDefinition(definition InputObjectTypeDefinition) (ref int) {
	d.InputObjectTypeDefinitions = append(d.InputObjectTypeDefinitions, definition)
	return len(d.InputObjectTypeDefinitions) - 1
}

func (d *Document) ImportInputObjectTypeDefinition(name, description string, argsRefs []int) (ref int) {
	return d.ImportInputObjectTypeDefinitionWithDirectives(name, description, argsRefs, nil)
}

func (d *Document) ImportInputObjectTypeDefinitionWithDirectives(name, description string, argsRefs []int, directiveRefs []int) (ref int) {
	definition := InputObjectTypeDefinition{
		Description:              d.ImportDescription(description),
		Name:                     d.Input.AppendInputString(name),
		HasInputFieldsDefinition: len(argsRefs) > 0,
		InputFieldsDefinition: InputValueDefinitionList{
			Refs: argsRefs,
		},
		HasDirectives: len(directiveRefs) > 0,
		Directives: DirectiveList{
			directiveRefs,
		},
	}

	ref = d.AddInputObjectTypeDefinition(definition)
	d.ImportRootNode(ref, NodeKindInputObjectTypeDefinition)

	return
}
