package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// UnionTypeDefinition
// example:
// union SearchResult = Photo | Person
type UnionTypeDefinition struct {
	Description         Description        // optional, describes union
	UnionLiteral        position.Position  // union
	Name                ByteSliceReference // e.g. SearchResult
	HasDirectives       bool
	Directives          DirectiveList     // optional, e.g. @foo
	Equals              position.Position // =
	HasUnionMemberTypes bool
	UnionMemberTypes    TypeList // optional, e.g. Photo | Person
}

func (d *Document) UnionTypeDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Name)
}

func (d *Document) UnionTypeDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Name))
}

func (d *Document) UnionTypeDefinitionDescriptionBytes(ref int) ByteSlice {
	if !d.UnionTypeDefinitions[ref].Description.IsDefined {
		return nil
	}
	return d.Input.ByteSlice(d.UnionTypeDefinitions[ref].Description.Content)
}

func (d *Document) UnionTypeDefinitionDescriptionString(ref int) string {
	return unsafebytes.BytesToString(d.UnionTypeDefinitionDescriptionBytes(ref))
}

func (d *Document) UnionMemberTypeIsFirst(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindUnionTypeDefinition:
		return len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs[0] == ref
	case NodeKindUnionTypeExtension:
		return len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs[0] == ref
	default:
		return false
	}
}

func (d *Document) UnionMemberTypeIsLast(ref int, ancestor Node) bool {
	switch ancestor.Kind {
	case NodeKindUnionTypeDefinition:
		return len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs[len(d.UnionTypeDefinitions[ancestor.Ref].UnionMemberTypes.Refs)-1] == ref
	case NodeKindUnionTypeExtension:
		return len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs) != 0 &&
			d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs[len(d.UnionTypeExtensions[ancestor.Ref].UnionMemberTypes.Refs)-1] == ref
	default:
		return false
	}
}

func (d *Document) UnionTypeDefinitionHasDirectives(ref int) bool {
	return d.UnionTypeDefinitions[ref].HasDirectives
}
