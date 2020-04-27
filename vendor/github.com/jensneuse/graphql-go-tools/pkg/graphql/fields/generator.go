package fields

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type Generator struct {
	walker  *astvisitor.Walker
	visitor *requestVisitor
}

func NewGenerator() *Generator {
	walker := astvisitor.NewWalker(48)
	visitor := requestVisitor{
		Walker: &walker,
	}

	walker.RegisterEnterFieldVisitor(&visitor)

	return &Generator{
		walker:  &walker,
		visitor: &visitor,
	}
}

func (g *Generator) Generate(operation, definition *ast.Document, report *operationreport.Report, data RequestTypes) {
	g.visitor.data = data
	g.visitor.operation = operation
	g.visitor.definition = definition
	g.walker.Walk(operation, definition, report)
}

type requestVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	data                  RequestTypes
}

func (p *requestVisitor) EnterField(ref int) {
	fieldName := p.operation.FieldNameString(ref)
	parentTypeName := p.definition.NodeNameString(p.EnclosingTypeDefinition)

	t, ok := p.data[parentTypeName]
	if !ok {
		t = make(RequestFields)
	}

	if _, ok := t[fieldName]; !ok {
		t[fieldName] = struct{}{}
	}

	p.data[parentTypeName] = t
}
