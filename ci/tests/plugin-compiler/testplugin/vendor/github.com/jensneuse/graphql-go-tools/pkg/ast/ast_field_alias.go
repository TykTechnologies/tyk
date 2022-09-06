package ast

import (
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type Alias struct {
	IsDefined bool
	Name      ByteSliceReference // optional, e.g. renamedField
	Colon     position.Position  // :
}

func (d *Document) FieldAliasOrNameBytes(ref int) ByteSlice {
	if d.FieldAliasIsDefined(ref) {
		return d.FieldAliasBytes(ref)
	}
	return d.FieldNameBytes(ref)
}

func (d *Document) FieldAliasOrNameString(ref int) string {
	return unsafebytes.BytesToString(d.FieldAliasOrNameBytes(ref))
}

func (d *Document) FieldAliasBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Fields[ref].Alias.Name)
}

func (d *Document) FieldAliasString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.Fields[ref].Alias.Name))
}

func (d *Document) FieldAliasIsDefined(ref int) bool {
	return d.Fields[ref].Alias.IsDefined
}

func (d *Document) RemoveFieldAlias(ref int) {
	d.Fields[ref].Alias.IsDefined = false
	d.Fields[ref].Alias.Name.Start = 0
	d.Fields[ref].Alias.Name.End = 0
}
