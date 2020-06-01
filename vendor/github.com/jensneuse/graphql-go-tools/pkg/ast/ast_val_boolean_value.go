package ast

// BooleanValues
// one of: true, false
type BooleanValue bool

func (d *Document) BooleanValue(ref int) BooleanValue {
	return d.BooleanValues[ref]
}

func (d *Document) BooleanValuesAreEqual(left, right int) bool {
	return d.BooleanValue(left) == d.BooleanValue(right)
}
