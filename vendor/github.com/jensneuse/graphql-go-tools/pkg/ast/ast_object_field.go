package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// ObjectField
// example:
// lon: 12.43
type ObjectField struct {
	Name  ByteSliceReference // e.g. lon
	Colon position.Position  // :
	Value Value              // e.g. 12.43
}

func (d *Document) ObjectField(ref int) ObjectField {
	return d.ObjectFields[ref]
}

func (d *Document) ObjectFieldNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.ObjectFields[ref].Name)
}

func (d *Document) ObjectFieldValue(ref int) Value {
	return d.ObjectFields[ref].Value
}

func (d *Document) ObjectFieldsAreEqual(left, right int) bool {
	return bytes.Equal(d.ObjectFieldNameBytes(left), d.ObjectFieldNameBytes(right)) &&
		d.ValuesAreEqual(d.ObjectFieldValue(left), d.ObjectFieldValue(right))
}

func (d *Document) ObjectValuesAreEqual(left, right int) bool {
	leftFields, rightFields := d.ObjectValues[left].Refs, d.ObjectValues[right].Refs
	if len(leftFields) != len(rightFields) {
		return false
	}
	for i := 0; i < len(leftFields); i++ {
		left, right = leftFields[i], rightFields[i]
		if !d.ObjectFieldsAreEqual(left, right) {
			return false
		}
	}
	return true
}
