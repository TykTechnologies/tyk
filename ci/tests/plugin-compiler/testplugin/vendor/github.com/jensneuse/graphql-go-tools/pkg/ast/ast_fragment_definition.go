package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// TypeCondition
// example:
// on User
type TypeCondition struct {
	On   position.Position // on
	Type int               // NamedType
}

// FragmentDefinition
// example:
// fragment friendFields on User {
//  id
//  name
//  profilePic(size: 50)
// }
type FragmentDefinition struct {
	FragmentLiteral position.Position  // fragment
	Name            ByteSliceReference // Name but not on, e.g. friendFields
	TypeCondition   TypeCondition      // e.g. on User
	Directives      DirectiveList      // optional, e.g. @foo
	SelectionSet    int                // e.g. { id }
	HasSelections   bool
}

func (d *Document) FragmentDefinitionRef(byName ByteSlice) (ref int, exists bool) {
	for i := range d.FragmentDefinitions {
		if bytes.Equal(byName, d.Input.ByteSlice(d.FragmentDefinitions[i].Name)) {
			return i, true
		}
	}
	return -1, false
}

func (d *Document) FragmentDefinitionTypeName(ref int) ByteSlice {
	return d.ResolveTypeNameBytes(d.FragmentDefinitions[ref].TypeCondition.Type)
}

func (d *Document) FragmentDefinitionNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FragmentDefinitions[ref].Name)
}

func (d *Document) FragmentDefinitionNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.FragmentDefinitions[ref].Name))
}

func (d *Document) FragmentDefinitionIsLastRootNode(ref int) bool {
	for i := range d.RootNodes {
		if d.RootNodes[i].Kind == NodeKindFragmentDefinition && d.RootNodes[i].Ref == ref {
			return len(d.RootNodes)-1 == i
		}
	}
	return false
}

func (d *Document) FragmentDefinitionIsUsed(name ByteSlice) bool {
	for _, i := range d.Index.ReplacedFragmentSpreads {
		if bytes.Equal(name, d.FragmentSpreadNameBytes(i)) {
			return true
		}
	}
	return false
}
