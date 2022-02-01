package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newRemoveObjectTypeDefinitionDirective(directives ...string) *removeObjectTypeDefinitionDirective {
	directivesSet := make(map[string]struct{}, len(directives))
	for _, directive := range directives {
		directivesSet[directive] = struct{}{}
	}

	return &removeObjectTypeDefinitionDirective{
		directives: directivesSet,
	}
}

type removeObjectTypeDefinitionDirective struct {
	operation  *ast.Document
	directives map[string]struct{}
}

func (r *removeObjectTypeDefinitionDirective) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(r)
	walker.RegisterEnterObjectTypeDefinitionVisitor(r)
}

func (r *removeObjectTypeDefinitionDirective) EnterDocument(operation, _ *ast.Document) {
	r.operation = operation
}

func (r *removeObjectTypeDefinitionDirective) EnterObjectTypeDefinition(ref int) {
	var refsForDeletion []int
	// select fields for deletion
	for _, directiveRef := range r.operation.ObjectTypeDefinitions[ref].Directives.Refs {
		directiveName := r.operation.DirectiveNameString(directiveRef)
		if _, ok := r.directives[directiveName]; ok {
			refsForDeletion = append(refsForDeletion, directiveRef)
		}
	}
	// delete directives
	r.operation.RemoveDirectivesFromNode(ast.Node{Kind: ast.NodeKindObjectTypeDefinition, Ref: ref}, refsForDeletion)
}
