package ast

import "github.com/jensneuse/graphql-go-tools/pkg/lexer/position"

type ListValue struct {
	LBRACK position.Position // [
	Refs   []int             // Path
	RBRACK position.Position // ]
}

func (d *Document) ListValuesAreEqual(left, right int) bool {
	leftValues, rightValues := d.ListValues[left].Refs, d.ListValues[right].Refs
	if len(leftValues) != len(rightValues) {
		return false
	}
	for i := 0; i < len(leftValues); i++ {
		left, right = leftValues[i], rightValues[i]
		leftValue, rightValue := d.Value(left), d.Value(right)
		if !d.ValuesAreEqual(leftValue, rightValue) {
			return false
		}
	}
	return true
}
