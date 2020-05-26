package ast

import (
	"bytes"
	"io"

	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/position"
)

type DirectiveList struct {
	Refs []int
}

type Directive struct {
	At           position.Position  // @
	Name         ByteSliceReference // e.g. include
	HasArguments bool
	Arguments    ArgumentList // e.g. (if: true)
}

func (d *Document) PrintDirective(ref int, w io.Writer) error {
	_, err := w.Write(literal.AT)
	if err != nil {
		return err
	}
	_, err = w.Write(d.Input.ByteSlice(d.Directives[ref].Name))
	if err != nil {
		return err
	}
	if d.Directives[ref].HasArguments {
		err = d.PrintArguments(d.Directives[ref].Arguments.Refs, w)
	}
	return err
}

func (d *Document) DirectiveName(ref int) ByteSliceReference {
	return d.Directives[ref].Name
}

func (d *Document) DirectiveNameBytes(ref int) ByteSlice {
	return d.Input.ByteSlice(d.Directives[ref].Name)
}

func (d *Document) DirectiveNameString(ref int) string {
	return d.Input.ByteSliceString(d.Directives[ref].Name)
}

func (d *Document) DirectiveIsFirst(directive int, ancestor Node) bool {
	directives := d.NodeDirectives(ancestor)
	return len(directives) != 0 && directives[0] == directive
}

func (d *Document) DirectiveIsLast(directive int, ancestor Node) bool {
	directives := d.NodeDirectives(ancestor)
	return len(directives) != 0 && directives[len(directives)-1] == directive
}

func (d *Document) DirectiveArgumentSet(ref int) []int {
	return d.Directives[ref].Arguments.Refs
}

func (d *Document) DirectiveArgumentValueByName(ref int, name ByteSlice) (Value, bool) {
	for i := 0; i < len(d.Directives[ref].Arguments.Refs); i++ {
		arg := d.Directives[ref].Arguments.Refs[i]
		if bytes.Equal(d.ArgumentNameBytes(arg), name) {
			return d.ArgumentValue(arg), true
		}
	}
	return Value{}, false
}

func (d *Document) DirectivesAreEqual(left, right int) bool {
	return d.Input.ByteSliceReferenceContentEquals(d.DirectiveName(left), d.DirectiveName(right)) &&
		d.ArgumentSetsAreEquals(d.DirectiveArgumentSet(left), d.DirectiveArgumentSet(right))
}

func (d *Document) DirectiveSetsAreEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
		leftDirective, rightDirective := left[i], right[i]
		if !d.DirectivesAreEqual(leftDirective, rightDirective) {
			return false
		}
	}
	return true
}

func (d *Document) AddDirective(directive Directive) (ref int) {
	d.Directives = append(d.Directives, directive)
	return len(d.Directives) - 1
}

func (d *Document) ImportDirective(name string, argRefs []int) (ref int) {
	directive := Directive{
		Name:         d.Input.AppendInputString(name),
		HasArguments: len(argRefs) > 0,
		Arguments: ArgumentList{
			Refs: argRefs,
		},
	}

	return d.AddDirective(directive)
}
