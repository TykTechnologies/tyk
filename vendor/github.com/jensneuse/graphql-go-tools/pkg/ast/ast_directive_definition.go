package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// DirectiveDefinition
// example:
// directive @example on FIELD
type DirectiveDefinition struct {
	Description             Description        // optional, describes the directive
	DirectiveLiteral        position.Position  // directive
	At                      position.Position  // @
	Name                    ByteSliceReference // e.g. example
	HasArgumentsDefinitions bool
	ArgumentsDefinition     InputValueDefinitionList // optional, e.g. (if: Boolean)
	On                      position.Position        // on
	DirectiveLocations      DirectiveLocations       // e.g. FIELD
}

func (d *Document) DirectiveDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.DirectiveDefinitions[ref].Name)
}

func (d *Document) DirectiveDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.DirectiveDefinitions[ref].Name))
}

func (d *Document) DirectiveDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.DirectiveDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.DirectiveDefinitions[ref].Description.Content)
}

func (d *Document) DirectiveDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.DirectiveDefinitionDescriptionBytes(ref))
}

func (d *Document) DirectiveArgumentInputValueDefinition(directiveName ByteSlice, argumentName ByteSlice) int {
	for i := range d.DirectiveDefinitions {
		if bytes.Equal(directiveName, d.Input.ByteSlice(d.DirectiveDefinitions[i].Name)) {
			for _, j := range d.DirectiveDefinitions[i].ArgumentsDefinition.Refs {
				if bytes.Equal(argumentName, d.Input.ByteSlice(d.InputValueDefinitions[j].Name)) {
					return j
				}
			}
		}
	}
	return -1
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueString(directiveName, argumentName string) string {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return ""
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindString {
		return ""
	}
	return d.StringValueContentString(defaultValue.Ref)
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueBool(directiveName, argumentName string) bool {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return false
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindBoolean {
		return false
	}
	return bool(d.BooleanValue(defaultValue.Ref))
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueInt64(directiveName, argumentName string) int64 {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return -1
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindInteger {
		return -1
	}
	return d.IntValueAsInt(defaultValue.Ref)
}

func (d *Document) DirectiveDefinitionArgumentDefaultValueFloat32(directiveName, argumentName string) float32 {
	inputValueDefinition := d.DirectiveArgumentInputValueDefinition(unsafebytes.StringToBytes(directiveName), unsafebytes.StringToBytes(argumentName))
	if inputValueDefinition == -1 {
		return -1
	}
	defaultValue := d.InputValueDefinitionDefaultValue(inputValueDefinition)
	if defaultValue.Kind != ValueKindFloat {
		return -1
	}
	return d.FloatValueAsFloat32(defaultValue.Ref)
}
