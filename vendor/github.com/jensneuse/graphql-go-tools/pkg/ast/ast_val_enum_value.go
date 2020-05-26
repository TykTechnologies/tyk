package ast

import "github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"

// EnumValue
// example:
// Name but not true or false or null
type EnumValue struct {
	Name ByteSliceReference // e.g. ORIGIN
}

func (d *Document) EnumValueName(ref int) ByteSliceReference {
	return d.EnumValues[ref].Name
}

func (d *Document) EnumValueNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.EnumValues[ref].Name)
}

func (d *Document) EnumValueNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.EnumValues[ref].Name))
}

func (d *Document) EnumValuesAreEqual(left, right int) bool {
	return d.Input.ByteSliceReferenceContentEquals(d.EnumValueName(left), d.EnumValueName(right))
}

func (d *Document) AddEnumValue(value EnumValue) (ref int) {
	d.EnumValues = append(d.EnumValues, value)
	return len(d.EnumValues) - 1
}

func (d *Document) ImportEnumValue(name ByteSlice) (ref int) {
	return d.AddEnumValue(EnumValue{
		Name: d.Input.AppendInputBytes(name),
	})
}
