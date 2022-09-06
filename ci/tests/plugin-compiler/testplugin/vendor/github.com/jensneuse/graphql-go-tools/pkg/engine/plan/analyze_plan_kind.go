package plan

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func AnalyzePlanKind(operation, definition *ast.Document, operationName string) (subscription, streaming bool, error error) {
	walker := astvisitor.NewWalker(48)
	visitor := &planKindVisitor{
		Walker:        &walker,
		operationName: operationName,
	}

	walker.RegisterEnterDocumentVisitor(visitor)
	walker.RegisterEnterOperationVisitor(visitor)
	walker.RegisterEnterDirectiveVisitor(visitor)

	var report operationreport.Report
	walker.Walk(operation, definition, &report)
	if report.HasErrors() {
		return false, false, report
	}
	subscription = visitor.isSubscription
	streaming = visitor.hasDeferDirective || visitor.hasStreamDirective
	return
}

type planKindVisitor struct {
	*astvisitor.Walker
	operation, definition                                 *ast.Document
	operationName                                         string
	isSubscription, hasStreamDirective, hasDeferDirective bool
}

func (p *planKindVisitor) EnterDirective(ref int) {
	directiveName := p.operation.DirectiveNameString(ref)
	ancestor := p.Ancestors[len(p.Ancestors)-1]
	switch ancestor.Kind {
	case ast.NodeKindField:
		switch directiveName {
		case "defer":
			p.hasDeferDirective = true
		case "stream":
			p.hasStreamDirective = true
		}
	}
}

func (p *planKindVisitor) EnterOperationDefinition(ref int) {
	name := p.operation.OperationDefinitionNameString(ref)
	if p.operationName != name {
		p.SkipNode()
		return
	}
	switch p.operation.OperationDefinitions[ref].OperationType {
	case ast.OperationTypeSubscription:
		p.isSubscription = true
	}
}

func (p *planKindVisitor) EnterDocument(operation, definition *ast.Document) {
	p.operation, p.definition = operation, definition
}
