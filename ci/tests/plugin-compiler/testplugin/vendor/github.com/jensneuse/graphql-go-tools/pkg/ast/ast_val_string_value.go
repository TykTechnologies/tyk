package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
)

// StringValue
// example:
// "foo"
type StringValue struct {
	BlockString bool               // """foo""" = blockString, "foo" string
	Content     ByteSliceReference // e.g. foo
}

func (d *Document) StringValue(ref int) StringValue {
	return d.StringValues[ref]
}

func (d *Document) StringValueContentBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.StringValues[ref].Content)
}

func (d *Document) StringValueContentString(ref int) string {
	return unsafebytes.BytesToString(d.StringValueContentBytes(ref))
}

func (d *Document) StringValueIsBlockString(ref int) bool {
	return d.StringValues[ref].BlockString
}

func (d *Document) StringValuesAreEquals(left, right int) bool {
	return d.StringValueIsBlockString(left) == d.StringValueIsBlockString(right) &&
		bytes.Equal(d.StringValueContentBytes(left), d.StringValueContentBytes(right))
}

func (d *Document) AddStringValue(value StringValue) (ref int) {
	d.StringValues = append(d.StringValues, value)
	return len(d.StringValues) - 1
}

func (d *Document) ImportStringValue(raw ByteSlice, isBlockString bool) (ref int) {
	return d.AddStringValue(StringValue{
		BlockString: isBlockString,
		Content:     d.Input.AppendInputBytes(raw),
	})
}
