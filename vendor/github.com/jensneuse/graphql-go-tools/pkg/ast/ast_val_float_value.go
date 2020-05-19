package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// FloatValue
// example:
// 13.37 / -13.37
type FloatValue struct {
	Negative     bool               // indicates if the value is negative
	NegativeSign position.Position  // optional -
	Raw          ByteSliceReference // e.g. 13.37
}

func (d *Document) FloatValueAsFloat32(ref int) (out float32) {
	in := d.Input.ByteSlice(d.FloatValues[ref].Raw)
	out = unsafebytes.BytesToFloat32(in)
	if d.FloatValues[ref].Negative {
		out = -out
	}
	return
}

func (d *Document) FloatValueIsNegative(ref int) bool {
	return d.FloatValues[ref].Negative
}

func (d *Document) FloatValueRaw(ref int) ByteSlice {
	return d.Input.ByteSlice(d.FloatValues[ref].Raw)
}

func (d *Document) FloatValuesAreEqual(left, right int) bool {
	return d.FloatValueIsNegative(left) == d.FloatValueIsNegative(right) &&
		bytes.Equal(d.FloatValueRaw(left), d.FloatValueRaw(right))
}
