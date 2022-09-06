package ast

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tidwall/sjson"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/quotes"
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type ValueKind int

const (
	ValueKindUnknown ValueKind = 4 + iota
	ValueKindString
	ValueKindBoolean
	ValueKindInteger
	ValueKindFloat
	ValueKindVariable
	ValueKindNull
	ValueKindList
	ValueKindObject
	ValueKindEnum
)

type Value struct {
	Kind ValueKind // e.g. 100 or "Bar"
	Ref  int
}

func (d *Document) ValueContentBytes(value Value) ByteSlice {
	switch value.Kind {
	case ValueKindEnum:
		return d.EnumValueNameBytes(value.Ref)
	case ValueKindString:
		return d.StringValueContentBytes(value.Ref)
	case ValueKindInteger:
		return d.IntValueRaw(value.Ref)
	case ValueKindFloat:
		return d.FloatValueRaw(value.Ref)
	}
	panic(fmt.Errorf("ValueContentBytes not implemented for ValueKind: %s", value.Kind))
}

func (d *Document) ValueContentString(value Value) string {
	return unsafebytes.BytesToString(d.ValueContentBytes(value))
}

func (d *Document) ValueToJSON(value Value) ([]byte, error) {
	switch value.Kind {
	case ValueKindNull:
		return literal.NULL, nil
	case ValueKindEnum:
		return quotes.WrapBytes(d.EnumValueNameBytes(value.Ref)), nil
	case ValueKindInteger:
		intValueBytes := d.IntValueRaw(value.Ref)
		if d.IntValueIsNegative(value.Ref) {
			return append(literal.SUB, intValueBytes...), nil
		}
		return intValueBytes, nil
	case ValueKindFloat:
		floatValueBytes := d.FloatValueRaw(value.Ref)
		if d.FloatValueIsNegative(value.Ref) {
			return append(literal.SUB, floatValueBytes...), nil
		}
		return floatValueBytes, nil
	case ValueKindBoolean:
		if value.Ref == 0 {
			return literal.FALSE, nil
		}
		return literal.TRUE, nil
	case ValueKindString:
		return quotes.WrapBytes(d.StringValueContentBytes(value.Ref)), nil
	case ValueKindList:
		out := []byte("[]")
		for _, i := range d.ListValues[value.Ref].Refs {
			item, err := d.ValueToJSON(d.Values[i])
			if err != nil {
				return nil, err
			}
			out, err = sjson.SetRawBytes(out, "-1", item)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case ValueKindObject:
		out := []byte("{}")
		for i := len(d.ObjectValues[value.Ref].Refs) - 1; i >= 0; i-- {
			ref := d.ObjectValues[value.Ref].Refs[i]
			fieldNameString := d.ObjectFieldNameString(ref)
			fieldValueBytes, err := d.ValueToJSON(d.ObjectFieldValue(ref))
			if err != nil {
				return nil, err
			}
			out, err = sjson.SetRawBytes(out, fieldNameString, fieldValueBytes)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("ValueToJSON: not implemented for kind: %s", value.Kind.String())
	}
}

// nolint
func (d *Document) PrintValue(value Value, w io.Writer) (err error) {
	switch value.Kind {
	case ValueKindBoolean:
		if d.BooleanValues[value.Ref] {
			_, err = w.Write(literal.TRUE)
		} else {
			_, err = w.Write(literal.FALSE)
		}
	case ValueKindString:
		_, err = w.Write(literal.QUOTE)
		_, err = w.Write(d.Input.ByteSlice(d.StringValues[value.Ref].Content))
		_, err = w.Write(literal.QUOTE)
	case ValueKindInteger:
		if d.IntValues[value.Ref].Negative {
			_, err = w.Write(literal.SUB)
		}
		_, err = w.Write(d.Input.ByteSlice(d.IntValues[value.Ref].Raw))
	case ValueKindFloat:
		if d.FloatValues[value.Ref].Negative {
			_, err = w.Write(literal.SUB)
		}
		_, err = w.Write(d.Input.ByteSlice(d.FloatValues[value.Ref].Raw))
	case ValueKindVariable:
		_, err = w.Write(literal.DOLLAR)
		_, err = w.Write(d.Input.ByteSlice(d.VariableValues[value.Ref].Name))
	case ValueKindNull:
		_, err = w.Write(literal.NULL)
	case ValueKindList:
		_, err = w.Write(literal.LBRACK)
		for i, j := range d.ListValues[value.Ref].Refs {
			err = d.PrintValue(d.Value(j), w)
			if err != nil {
				return
			}
			if i != len(d.ListValues[value.Ref].Refs)-1 {
				_, err = w.Write(literal.COMMA)
			}
		}
		_, err = w.Write(literal.RBRACK)
	case ValueKindObject:
		_, err = w.Write(literal.LBRACE)
		for i, j := range d.ObjectValues[value.Ref].Refs {
			_, err = w.Write(d.ObjectFieldNameBytes(j))
			if err != nil {
				return
			}
			_, err = w.Write(literal.COLON)
			if err != nil {
				return
			}
			_, err = w.Write(literal.SPACE)
			if err != nil {
				return
			}
			err = d.PrintValue(d.ObjectFieldValue(j), w)
			if err != nil {
				return
			}
			if i != len(d.ObjectValues[value.Ref].Refs)-1 {
				_, err = w.Write(literal.COMMA)
				if err != nil {
					return
				}
			}
		}
		_, err = w.Write(literal.RBRACE)
	case ValueKindEnum:
		_, err = w.Write(d.Input.ByteSlice(d.EnumValues[value.Ref].Name))
	}
	return
}

func (d *Document) PrintValueBytes(value Value, buf []byte) ([]byte, error) {
	if buf == nil {
		buf = make([]byte, 0, 24)
	}
	b := bytes.NewBuffer(buf)
	err := d.PrintValue(value, b)
	return b.Bytes(), err
}

func (d *Document) Value(ref int) Value {
	return d.Values[ref]
}

func (d *Document) ValuesAreEqual(left, right Value) bool {
	if left.Kind != right.Kind {
		return false
	}
	switch left.Kind {
	case ValueKindString:
		return d.StringValuesAreEquals(left.Ref, right.Ref)
	case ValueKindBoolean:
		return d.BooleanValuesAreEqual(left.Ref, right.Ref)
	case ValueKindInteger:
		return d.IntValuesAreEquals(left.Ref, right.Ref)
	case ValueKindFloat:
		return d.FloatValuesAreEqual(left.Ref, right.Ref)
	case ValueKindVariable:
		return d.VariableValuesAreEqual(left.Ref, right.Ref)
	case ValueKindNull:
		return true
	case ValueKindList:
		return d.ListValuesAreEqual(left.Ref, right.Ref)
	case ValueKindObject:
		return d.ObjectValuesAreEqual(left.Ref, right.Ref)
	case ValueKindEnum:
		return d.EnumValuesAreEqual(left.Ref, right.Ref)
	default:
		return false
	}
}

func (d *Document) AddValue(value Value) (ref int) {
	d.Values = append(d.Values, value)
	return len(d.Values) - 1
}
