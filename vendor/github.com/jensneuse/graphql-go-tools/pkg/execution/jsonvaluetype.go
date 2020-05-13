//go:generate stringer -type=JSONValueType
package execution

import (
	"bytes"
	"fmt"
	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/escape"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"io"
)

type JSONValueType int

const (
	UnknownValueType JSONValueType = iota
	StringValueType
	IntegerValueType
	FloatValueType
	BooleanValueType
)

type ErrJSONValueTypeValueIncompatible struct {
	value     []byte
	valueType JSONValueType
}

func (e ErrJSONValueTypeValueIncompatible) Error() string {
	return fmt.Sprintf("JSONValueType.writeValue: cannot write %s as %s", unsafebytes.BytesToString(e.value), e.valueType)
}

func (i JSONValueType) writeValue(value, escapeBuf []byte, out io.Writer) (n int, err error) {

	if len(value) == 0 || bytes.Equal(value, literal.NULL) {
		return i.write(n, err, out, literal.NULL)
	}

	switch i {
	case StringValueType:
		n, err = i.write(n, err, out, literal.QUOTE)
		n, err = i.write(n, err, out, escape.Bytes(value, escapeBuf))
		return i.write(n, err, out, literal.QUOTE)
	case IntegerValueType:
		if !unsafebytes.BytesIsValidInt64(value) {
			return n, ErrJSONValueTypeValueIncompatible{
				value:     value,
				valueType: i,
			}
		}
		return i.write(n, err, out, value)
	case FloatValueType:
		if !unsafebytes.BytesIsValidFloat32(value) {
			return n, ErrJSONValueTypeValueIncompatible{
				value:     value,
				valueType: i,
			}
		}
		return i.write(n, err, out, value)
	case BooleanValueType:
		if !unsafebytes.BytesIsValidBool(value) {
			return n, ErrJSONValueTypeValueIncompatible{
				value:     value,
				valueType: i,
			}
		}
		if unsafebytes.BytesToBool(value) {
			return i.write(n, err, out, literal.TRUE)
		} else {
			return i.write(n, err, out, literal.FALSE)
		}
	default:
		return n, ErrJSONValueTypeValueIncompatible{
			value:     value,
			valueType: i,
		}
	}
}

func (i JSONValueType) write(n int, err error, out io.Writer, value []byte) (int, error) {
	if err != nil {
		return n, err
	}
	written, err := out.Write(value)
	return n + written, err
}
