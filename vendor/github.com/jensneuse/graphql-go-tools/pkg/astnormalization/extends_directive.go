package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
)

var extendsDirectiveName = "extends"

type extendsDirectiveVisitor struct {
	document *ast.Document
}

func extendsDirective(walker *astvisitor.Walker) {
	v := &extendsDirectiveVisitor{}
	walker.RegisterEnterDocumentVisitor(v)
	walker.RegisterEnterObjectTypeDefinitionVisitor(v)
	walker.RegisterEnterInterfaceTypeDefinitionVisitor(v)
}

func (v *extendsDirectiveVisitor) EnterDocument(document, _ *ast.Document) {
	v.document = document
}

func (v *extendsDirectiveVisitor) EnterObjectTypeDefinition(ref int) {
	if !v.document.ObjectTypeDefinitions[ref].Directives.HasDirectiveByName(v.document, extendsDirectiveName) {
		return
	}
	for i := range v.document.RootNodes {
		if v.document.RootNodes[i].Ref == ref && v.document.RootNodes[i].Kind == ast.NodeKindObjectTypeDefinition {
			// give this node a new NodeKind of ObjectTypeExtension
			newRef := v.document.AddObjectTypeDefinitionExtension(ast.ObjectTypeExtension{ObjectTypeDefinition: v.document.ObjectTypeDefinitions[ref]})
			// reflect changes inside the root nodes
			v.document.UpdateRootNode(i, newRef, ast.NodeKindObjectTypeExtension)
			// only remove @extends if the nodes was updated
			v.document.ObjectTypeExtensions[newRef].Directives.RemoveDirectiveByName(v.document, extendsDirectiveName)
			// update index
			oldIndexNode := ast.Node{
				Kind: ast.NodeKindObjectTypeDefinition,
				Ref:  ref,
			}

			v.document.Index.ReplaceNode(v.document.ObjectTypeExtensionNameBytes(newRef), oldIndexNode, ast.Node{
				Kind: ast.NodeKindObjectTypeExtension,
				Ref:  newRef,
			})

			break
		}
	}

}

func (v *extendsDirectiveVisitor) EnterInterfaceTypeDefinition(ref int) {
	if !v.document.InterfaceTypeDefinitions[ref].Directives.HasDirectiveByName(v.document, extendsDirectiveName) {
		return
	}
	for i := range v.document.RootNodes {
		if v.document.RootNodes[i].Kind != ast.NodeKindInterfaceTypeDefinition || v.document.RootNodes[i].Ref != ref {
			continue
		}

		newRef := v.document.AddInterfaceTypeExtension(ast.InterfaceTypeExtension{
			InterfaceTypeDefinition: v.document.InterfaceTypeDefinitions[ref],
		})

		v.document.UpdateRootNode(i, newRef, ast.NodeKindInterfaceTypeExtension)
		v.document.InterfaceTypeExtensions[newRef].Directives.RemoveDirectiveByName(v.document, extendsDirectiveName)

		oldIndexNode := ast.Node{
			Kind: ast.NodeKindInterfaceTypeDefinition,
			Ref:  ref,
		}

		v.document.Index.ReplaceNode(v.document.InterfaceTypeExtensionNameBytes(newRef), oldIndexNode, ast.Node{
			Kind: ast.NodeKindInterfaceTypeExtension,
			Ref:  newRef,
		})

		return
	}
}
