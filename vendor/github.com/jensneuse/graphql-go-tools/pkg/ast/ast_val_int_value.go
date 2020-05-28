package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// IntValue
// example:
// 123 / -123
type IntValue struct {
	Negative     bool               // indicates if the value is negative
	NegativeSign position.Position  // optional -
	Raw          ByteSliceReference // e.g. 123
}

func (d *Document) IntValueAsInt(ref int) (out int64) {
	in := d.Input.ByteSlice(d.IntValues[ref].Raw)
	out = unsafebytes.BytesToInt64(in)
	if d.IntValues[ref].Negative {
		out = -out
	}
	return
}

func (d *Document) IntValue(ref int) IntValue {
	return d.IntValues[ref]
}

func (d *Document) IntValueIsNegative(ref int) bool {
	return d.IntValues[ref].Negative
}

func (d *Document) IntValueRaw(ref int) ByteSlice {
	return d.Input.ByteSlice(d.IntValues[ref].Raw)
}

func (d *Document) IntValuesAreEquals(left, right int) bool {
	return d.IntValueIsNegative(left) == d.IntValueIsNegative(right) &&
		bytes.Equal(d.IntValueRaw(left), d.IntValueRaw(right))
}

func (d *Document) AddIntValue(value IntValue) (ref int) {
	d.IntValues = append(d.IntValues, value)
	return len(d.IntValues) - 1
}

func (d *Document) ImportIntValue(raw ByteSlice, isNegative bool) (ref int) {
	return d.AddIntValue(IntValue{
		Negative: isNegative,
		Raw:      d.Input.AppendInputBytes(raw),
	})
}
