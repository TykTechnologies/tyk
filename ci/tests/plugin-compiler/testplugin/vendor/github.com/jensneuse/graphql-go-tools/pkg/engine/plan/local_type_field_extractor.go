package plan

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/astprinter"
	"github.com/jensneuse/graphql-go-tools/pkg/asttransform"
	"github.com/jensneuse/graphql-go-tools/pkg/federation"
)

const (
	federationKeyDirectiveName      = "key"
	federationRequireDirectiveName  = "requires"
	federationExternalDirectiveName = "external"
)

// LocalTypeFieldExtractor takes an ast.Document as input
// and generates the TypeField configuration for both root fields & child fields
// If a type is a federation entity (annotated with @key directive)
// and a field is is extended, this field will be skipped
// so that only "local" fields will be generated
type LocalTypeFieldExtractor struct {
	document *ast.Document
}

func NewLocalTypeFieldExtractor(document *ast.Document) *LocalTypeFieldExtractor {
	return &LocalTypeFieldExtractor{document: document}
}

// GetAllNodes returns all Root- & ChildNodes
func (e *LocalTypeFieldExtractor) GetAllNodes() (rootNodes, childNodes []TypeField) {
	rootNodes = e.getAllRootNodes()
	childNodes = e.getAllChildNodes(rootNodes)
	return
}

func (e *LocalTypeFieldExtractor) getAllRootNodes() []TypeField {
	var rootNodes []TypeField

	for _, astNode := range e.document.RootNodes {
		switch astNode.Kind {
		case ast.NodeKindObjectTypeExtension, ast.NodeKindObjectTypeDefinition:
			e.addRootNodes(astNode, &rootNodes)
		}
	}

	return rootNodes
}

func (e *LocalTypeFieldExtractor) getAllChildNodes(rootNodes []TypeField) []TypeField {
	var childNodes []TypeField

	for i := range rootNodes {
		fieldNameToRef := make(map[string]int, len(rootNodes[i].FieldNames))

		rootNodeASTNode, exists := e.document.Index.FirstNodeByNameStr(rootNodes[i].TypeName)
		if !exists {
			continue
		}

		fieldRefs := e.document.NodeFieldDefinitions(rootNodeASTNode)
		for _, fieldRef := range fieldRefs {
			fieldName := e.document.FieldDefinitionNameString(fieldRef)
			fieldNameToRef[fieldName] = fieldRef
		}

		for _, fieldName := range rootNodes[i].FieldNames {
			fieldRef := fieldNameToRef[fieldName]

			fieldTypeName := e.document.NodeNameString(e.document.FieldDefinitionTypeNode(fieldRef))
			e.findChildNodesForType(fieldTypeName, &childNodes)
		}
	}

	return childNodes
}

func (e *LocalTypeFieldExtractor) findChildNodesForType(typeName string, childNodes *[]TypeField) {
	node, exists := e.document.Index.FirstNodeByNameStr(typeName)
	if !exists {
		return
	}

	fieldsRefs := e.document.NodeFieldDefinitions(node)

	for _, fieldRef := range fieldsRefs {
		fieldName := e.document.FieldDefinitionNameString(fieldRef)

		if added := e.addChildTypeFieldName(typeName, fieldName, childNodes); !added {
			continue
		}

		fieldTypeName := e.document.NodeNameString(e.document.FieldDefinitionTypeNode(fieldRef))
		e.findChildNodesForType(fieldTypeName, childNodes)
	}
}

func (e *LocalTypeFieldExtractor) addChildTypeFieldName(typeName, fieldName string, childNodes *[]TypeField) bool {
	for i := range *childNodes {
		if (*childNodes)[i].TypeName != typeName {
			continue
		}

		for _, field := range (*childNodes)[i].FieldNames {
			if field == fieldName {
				return false
			}
		}

		(*childNodes)[i].FieldNames = append((*childNodes)[i].FieldNames, fieldName)
		return true
	}

	*childNodes = append(*childNodes, TypeField{
		TypeName:   typeName,
		FieldNames: []string{fieldName},
	})

	return true
}

func (e *LocalTypeFieldExtractor) addRootNodes(astNode ast.Node, rootNodes *[]TypeField) {
	typeName := e.document.NodeNameString(astNode)

	// we need to first build the base schema so that we get a valid Index
	// to look up if typeName is a RootOperationTypeName
	// the service SDL itself might use ObjectTypeExtension types which will not be indexed
	document := e.baseSchema()

	// node should be an entity or a root operation type definition
	// if document == nil, there are no root operation type definitions in this document
	if !e.isEntity(astNode) && (document == nil || !document.Index.IsRootOperationTypeNameString(typeName)) {
		return
	}

	var fieldNames []string

	fieldRefs := e.document.NodeFieldDefinitions(astNode)
	for _, fieldRef := range fieldRefs {
		// check if field definition is external (has external directive)
		if e.document.FieldDefinitionHasNamedDirective(fieldRef, federationExternalDirectiveName) {
			continue
		}

		fieldName := e.document.FieldDefinitionNameString(fieldRef)
		fieldNames = append(fieldNames, fieldName)
	}

	if len(fieldNames) == 0 {
		return
	}

	*rootNodes = append(*rootNodes, TypeField{
		TypeName:   typeName,
		FieldNames: fieldNames,
	})
}

func (e *LocalTypeFieldExtractor) baseSchema() *ast.Document {
	schemaSDL, err := astprinter.PrintString(e.document, nil)
	if err != nil {
		return nil
	}
	baseSchemaSDL, err := federation.BuildBaseSchemaDocument(schemaSDL)
	if err != nil {
		return nil
	}
	document, report := astparser.ParseGraphqlDocumentString(baseSchemaSDL)
	if report.HasErrors() {
		return nil
	}
	err = asttransform.MergeDefinitionWithBaseSchema(&document)
	if err != nil {
		return nil
	}
	mergedSDL, err := astprinter.PrintString(&document, nil)
	if err != nil {
		return nil
	}
	mergedDocument, report := astparser.ParseGraphqlDocumentString(mergedSDL)
	if report.HasErrors() {
		return nil
	}
	return &mergedDocument
}

// isEntity checks if node is an Entity according to the federation spec
// by checking if it is annotated with the "key" directive
func (e *LocalTypeFieldExtractor) isEntity(astNode ast.Node) bool {
	directiveRefs := e.document.NodeDirectives(astNode)

	for _, directiveRef := range directiveRefs {
		if directiveName := e.document.DirectiveNameString(directiveRef); directiveName == federationKeyDirectiveName {
			return true
		}
	}

	return false
}
