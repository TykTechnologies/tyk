package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newRemoveInterfaceDefinitionDirective(directives ...string) *removeInterfaceDefinitionDirective {
	directivesSet := make(map[string]struct{}, len(directives))
	for _, directive := range directives {
		directivesSet[directive] = struct{}{}
	}

	return &removeInterfaceDefinitionDirective{
		directives: directivesSet,
	}
}

type removeInterfaceDefinitionDirective struct {
	*astvisitor.Walker
	operation  *ast.Document
	directives map[string]struct{}
}

func (r *removeInterfaceDefinitionDirective) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(r)
	walker.RegisterEnterInterfaceTypeDefinitionVisitor(r)
}

func (r *removeInterfaceDefinitionDirective) EnterDocument(operation, _ *ast.Document) {
	r.operation = operation
}

func (r *removeInterfaceDefinitionDirective) EnterInterfaceTypeDefinition(ref int) {
	var refsForDeletion []int
	// select fields for deletion
	for _, directiveRef := range r.operation.InterfaceTypeDefinitions[ref].Directives.Refs {
		directiveName := r.operation.DirectiveNameString(directiveRef)
		if _, ok := r.directives[directiveName]; ok {
			refsForDeletion = append(refsForDeletion, directiveRef)
		}
	}
	// delete directives
	r.operation.RemoveDirectivesFromNode(ast.Node{Kind: ast.NodeKindInterfaceTypeDefinition, Ref: ref}, refsForDeletion)
}
