package astnormalization

import (
	"bytes"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

func directiveIncludeSkip(walker *astvisitor.Walker) {
	visitor := directiveIncludeSkipVisitor{
		Walker: walker,
	}
	walker.RegisterEnterDocumentVisitor(&visitor)
	walker.RegisterEnterDirectiveVisitor(&visitor)
}

type directiveIncludeSkipVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
}

func (d *directiveIncludeSkipVisitor) EnterDocument(operation, definition *ast.Document) {
	d.operation = operation
	d.definition = definition
}

func (d *directiveIncludeSkipVisitor) EnterDirective(ref int) {

	name := d.operation.DirectiveNameBytes(ref)

	switch {
	case bytes.Equal(name, literal.INCLUDE):
		d.handleInclude(ref)
	case bytes.Equal(name, literal.SKIP):
		d.handleSkip(ref)
	}
}

func (d *directiveIncludeSkipVisitor) handleSkip(ref int) {
	if len(d.operation.Directives[ref].Arguments.Refs) != 1 {
		return
	}
	arg := d.operation.Directives[ref].Arguments.Refs[0]
	if !bytes.Equal(d.operation.ArgumentNameBytes(arg), literal.IF) {
		return
	}
	value := d.operation.ArgumentValue(arg)
	if value.Kind != ast.ValueKindBoolean {
		return
	}
	include := d.operation.BooleanValue(value.Ref)
	switch include {
	case false:
		d.operation.RemoveDirectiveFromNode(d.Ancestors[len(d.Ancestors)-1], ref)
	case true:
		if len(d.Ancestors) < 2 {
			return
		}
		d.operation.RemoveNodeFromNode(d.Ancestors[len(d.Ancestors)-1], d.Ancestors[len(d.Ancestors)-2])
	}
}

func (d *directiveIncludeSkipVisitor) handleInclude(ref int) {
	if len(d.operation.Directives[ref].Arguments.Refs) != 1 {
		return
	}
	arg := d.operation.Directives[ref].Arguments.Refs[0]
	if !bytes.Equal(d.operation.ArgumentNameBytes(arg), literal.IF) {
		return
	}
	value := d.operation.ArgumentValue(arg)
	if value.Kind != ast.ValueKindBoolean {
		return
	}
	include := d.operation.BooleanValue(value.Ref)
	switch include {
	case true:
		d.operation.RemoveDirectiveFromNode(d.Ancestors[len(d.Ancestors)-1], ref)
	case false:
		if len(d.Ancestors) < 2 {
			return
		}
		d.operation.RemoveNodeFromNode(d.Ancestors[len(d.Ancestors)-1], d.Ancestors[len(d.Ancestors)-2])
	}
}
