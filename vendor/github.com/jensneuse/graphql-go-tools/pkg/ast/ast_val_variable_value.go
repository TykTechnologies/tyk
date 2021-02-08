package ast

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

// VariableValue
// example:
// $devicePicSize
type VariableValue struct {
	Dollar position.Position  // $
	Name   ByteSliceReference // e.g. devicePicSize
}

func (d *Document) VariableValueNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.VariableValues[ref].Name)
}

func (d *Document) VariableValueNameString(ref int) string {
	return unsafebytes.BytesToString(d.Input.ByteSlice(d.VariableValues[ref].Name))
}

func (d *Document) VariableValuesAreEqual(left, right int) bool {
	return bytes.Equal(d.VariableValueNameBytes(left), d.VariableValueNameBytes(right))
}

func (d *Document) AddVariableValue(value VariableValue) (ref int) {
	d.VariableValues = append(d.VariableValues, value)
	return len(d.VariableValues) - 1
}

func (d *Document) ImportVariableValue(name ByteSlice) (ref int) {
	return d.AddVariableValue(VariableValue{
		Name: d.Input.AppendInputBytes(name),
	})
}

func (d *Document) AddVariableValueArgument(argName, variableName []byte) (variableValueRef, argRef int) {
	variable := VariableValue{
		Name: d.Input.AppendInputBytes(variableName),
	}
	d.VariableValues = append(d.VariableValues, variable)
	variableValueRef = len(d.VariableValues) - 1
	arg := Argument{
		Name: d.Input.AppendInputBytes(argName),
		Value: Value{
			Kind: ValueKindVariable,
			Ref:  variableValueRef,
		},
	}
	d.Arguments = append(d.Arguments, arg)
	argRef = len(d.Arguments) - 1
	return
}
