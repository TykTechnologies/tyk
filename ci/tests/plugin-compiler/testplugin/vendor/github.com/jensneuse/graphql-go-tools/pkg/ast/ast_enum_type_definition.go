package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// EnumTypeDefinition
// example:
// enum Direction {
//  NORTH
//  EAST
//  SOUTH
//  WEST
// }
type EnumTypeDefinition struct {
	Description             Description        // optional, describes enum
	EnumLiteral             position.Position  // enum
	Name                    ByteSliceReference // e.g. Direction
	HasDirectives           bool
	Directives              DirectiveList // optional, e.g. @foo
	HasEnumValuesDefinition bool
	EnumValuesDefinition    EnumValueDefinitionList // optional, e.g. { NORTH EAST }
}

func (d *Document) EnumTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Name)
}

func (d *Document) EnumTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Name))
}

func (d *Document) EnumTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.EnumTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.EnumTypeDefinitions[ref].Description.Content)
}

func (d *Document) EnumTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.EnumTypeDefinitionDescriptionBytes(ref))
}

func (d *Document) EnumTypeDefinitionHasDirectives(ref int) bool {
	return d.EnumTypeDefinitions[ref].HasDirectives
}

func (d *Document) EnumTypeDefinitionHasEnumValueDefinition(ref int) bool {
	return d.EnumTypeDefinitions[ref].HasEnumValuesDefinition
}

func (d *Document) EnumTypeDefinitionContainsEnumValue(enumTypeDef int, valueName ByteSlice) bool {
	for _, i := range d.EnumTypeDefinitions[enumTypeDef].EnumValuesDefinition.Refs {
		if bytes.Equal(valueName, d.EnumValueDefinitionNameBytes(i)) {
			return true
		}
	}
	return false
}

func (d *Document) AddEnumTypeDefinition(definition EnumTypeDefinition) (ref int) {
	d.EnumTypeDefinitions = append(d.EnumTypeDefinitions, definition)
	return len(d.EnumTypeDefinitions) - 1
}

func (d *Document) ImportEnumTypeDefinition(name, description string, valueRefs []int) (ref int) {
	return d.ImportEnumTypeDefinitionWithDirectives(name, description, valueRefs, nil)
}

func (d *Document) ImportEnumTypeDefinitionWithDirectives(name, description string, valueRefs []int, directiveRefs []int) (ref int) {
	definition := EnumTypeDefinition{
		Description:             d.ImportDescription(description),
		Name:                    d.Input.AppendInputString(name),
		HasEnumValuesDefinition: len(valueRefs) > 0,
		EnumValuesDefinition: EnumValueDefinitionList{
			Refs: valueRefs,
		},
		HasDirectives: len(directiveRefs) > 0,
		Directives: DirectiveList{
			Refs: directiveRefs,
		},
	}

	ref = d.AddEnumTypeDefinition(definition)
	d.ImportRootNode(ref, NodeKindEnumTypeDefinition)

	return
}
