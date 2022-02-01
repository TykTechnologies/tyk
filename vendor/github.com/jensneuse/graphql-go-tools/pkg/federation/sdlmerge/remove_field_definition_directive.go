package sdlmerge

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

func newRemoveFieldDefinitionDirective(directives ...string) *removeFieldDefinitionDirective {
	directivesSet := make(map[string]struct{}, len(directives))
	for _, directive := range directives {
		directivesSet[directive] = struct{}{}
	}

	return &removeFieldDefinitionDirective{
		directives: directivesSet,
	}
}

type removeFieldDefinitionDirective struct {
	operation  *ast.Document
	directives map[string]struct{}
}

func (r *removeFieldDefinitionDirective) Register(walker *astvisitor.Walker) {
	walker.RegisterEnterDocumentVisitor(r)
	walker.RegisterEnterFieldDefinitionVisitor(r)
}

func (r *removeFieldDefinitionDirective) EnterDocument(operation, _ *ast.Document) {
	r.operation = operation
}

func (r *removeFieldDefinitionDirective) EnterFieldDefinition(ref int) {
	var refsForDeletion []int
	// select directives for deletion
	for _, directiveRef := range r.operation.FieldDefinitions[ref].Directives.Refs {
		directiveName := r.operation.DirectiveNameString(directiveRef)
		if _, ok := r.directives[directiveName]; ok {
			refsForDeletion = append(refsForDeletion, directiveRef)
		}
	}
	// delete directives
	r.operation.RemoveDirectivesFromNode(ast.Node{Kind: ast.NodeKindFieldDefinition, Ref: ref}, refsForDeletion)
}
