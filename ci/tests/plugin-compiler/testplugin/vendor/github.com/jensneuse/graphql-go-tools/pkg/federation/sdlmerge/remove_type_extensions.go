package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newRemoveMergedTypeExtensions() *removeMergedTypeExtensionsVisitor {
	return &removeMergedTypeExtensionsVisitor{}
}

type removeMergedTypeExtensionsVisitor struct {
}

func (r *removeMergedTypeExtensionsVisitor) Register(walker *astvisitor.Walker) {
	walker.RegisterLeaveDocumentVisitor(r)
}

func (r *removeMergedTypeExtensionsVisitor) LeaveDocument(operation, definition *ast.Document) {
	operation.RemoveMergedTypeExtensions()
}
