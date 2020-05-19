package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type EnumValueDefinitionList struct {
	LBRACE position.Position // {
	Refs   []int             //
	RBRACE position.Position // }
}

// EnumValueDefinition
// example:
// "NORTH enum value" NORTH @foo
type EnumValueDefinition struct {
	Description   Description        // optional, describes enum value
	EnumValue     ByteSliceReference // e.g. NORTH (Name but not true, false or null
	HasDirectives bool
	Directives    DirectiveList // optional, e.g. @foo
}

func (d *Document) EnumValueDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumValueDefinitions[ref].EnumValue)
}

func (d *Document) EnumValueDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumValueDefinitions[ref].EnumValue))
}

func (d *Document) EnumValueDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.EnumValueDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.EnumValueDefinitions[ref].Description.Content)
}

func (d *Document) EnumValueDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.EnumValueDefinitionDescriptionBytes(ref))
}

func (d *Document) EnumValueDefinitionIsFirst(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindEnumTypeDefinition:
		return d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs[0] == ref
	case NodeKindEnumTypeExtension:
		return d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs[0] == ref
	default:
		return false
	}
}

func (d *Document) EnumValueDefinitionIsLast(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindEnumTypeDefinition:
		return d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs[len(d.EnumTypeDefinitions[ancestor.Ref].EnumValuesDefinition.Refs)-1] == ref
	case NodeKindEnumTypeExtension:
		return d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs != nil &&
			d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs[len(d.EnumTypeExtensions[ancestor.Ref].EnumValuesDefinition.Refs)-1] == ref
	default:
		return false
	}
}
