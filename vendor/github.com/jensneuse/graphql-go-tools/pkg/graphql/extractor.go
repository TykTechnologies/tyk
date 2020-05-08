package graphql

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type Extractor struct {
	walker  *astvisitor.Walker
	visitor *requestVisitor
}

func NewExtractor() *Extractor {
	walker := astvisitor.NewWalker(48)
	visitor := requestVisitor{
		Walker: &walker,
	}

	walker.RegisterEnterFieldVisitor(&visitor)

	return &Extractor{
		walker:  &walker,
		visitor: &visitor,
	}
}

func (e *Extractor) ExtractFieldsFromRequest(request *Request, schema *Schema, report *operationreport.Report, data RequestTypes) {
	if !request.IsNormalized() {
		result, err := request.Normalize(schema)
		if err != nil {
			report.AddInternalError(err)
		}

		if !result.Successful {
			report.AddInternalError(result.Errors)
		}
	}

	e.visitor.data = data
	e.visitor.operation = &request.document
	e.visitor.definition = &schema.document
	e.walker.Walk(&request.document, &schema.document, report)
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
