package ast

import (
	"bytes"
	"io"

	"github.com/jensneuse/graphql-go-tools/internal/pkg/unsafebytes"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type ArgumentList struct {
	LPAREN position.Position
	Refs   []int // Argument
	RPAREN position.Position
}

type Argument struct {
	Name  ByteSliceReference // e.g. foo
	Colon position.Position  // :
	Value Value              // e.g. 100 or "Bar"
}

func (d *Document) PrintArgument(ref int, w io.Writer) error {
	_, err := w.Write(d.Input.ByteSlice(d.Arguments[ref].Name))
	if err != nil {
		return err
	}
	_, err = w.Write(literal.COLON)
	if err != nil {
		return err
	}
	_, err = w.Write(literal.SPACE)
	if err != nil {
		return err
	}
	return d.PrintValue(d.Arguments[ref].Value, w)
}

func (d *Document) PrintArguments(refs []int, w io.Writer) (err error) {
	_, err = w.Write(literal.LPAREN)
	if err != nil {
		return
	}
	for i, j := range refs {
		err = d.PrintArgument(j, w)
		if err != nil {
			return
		}
		if i != len(refs)-1 {
			_, err = w.Write(literal.COMMA)
			if err != nil {
				return
			}
			_, err = w.Write(literal.SPACE)
			if err != nil {
				return
			}
		}
	}
	_, err = w.Write(literal.RPAREN)
	return
}

func (d *Document) ArgumentNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Arguments[ref].Name)
}

func (d *Document) ArgumentNameString(ref int) string {
	return unsafebytes.BytesToString(d.ArgumentNameBytes(ref))
}

func (d *Document) ArgumentValue(ref int) Value {
	return d.Arguments[ref].Value
}

func (d *Document) ArgumentsAreEqual(left, right int) bool {
	return bytes.Equal(d.ArgumentNameBytes(left), d.ArgumentNameBytes(right)) &&
		d.ValuesAreEqual(d.ArgumentValue(left), d.ArgumentValue(right))
}

func (d *Document) ArgumentSetsAreEquals(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		leftArgument, rightArgument := left[i], right[i]
		if !d.ArgumentsAreEqual(leftArgument, rightArgument) {
			return false
		}
	}
	return true
}

func (d *Document) ArgumentsBefore(ancestor Node, argument int) []int {
	switch ancestor.Kind {
	case NodeKindField:
		for i, j := range d.Fields[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Fields[ancestor.Ref].Arguments.Refs[:i]
			}
		}
	case NodeKindDirective:
		for i, j := range d.Directives[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Directives[ancestor.Ref].Arguments.Refs[:i]
			}
		}
	}
	return nil
}

func (d *Document) ArgumentsAfter(ancestor Node, argument int) []int {
	switch ancestor.Kind {
	case NodeKindField:
		for i, j := range d.Fields[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Fields[ancestor.Ref].Arguments.Refs[i+1:]
			}
		}
	case NodeKindDirective:
		for i, j := range d.Directives[ancestor.Ref].Arguments.Refs {
			if argument == j {
				return d.Directives[ancestor.Ref].Arguments.Refs[i+1:]
			}
		}
	}
	return nil
}
