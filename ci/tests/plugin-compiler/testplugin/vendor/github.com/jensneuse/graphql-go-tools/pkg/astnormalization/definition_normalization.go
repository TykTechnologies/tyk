package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// NormalizeDefinition creates a default DefinitionNormalizer and applies all rules to a given AST
// In case you're using DefinitionNormalizer in a hot path you shouldn't be using this function.
// Create a new DefinitionNormalizer using NewDefinitionNormalizer() instead and re-use it.
func NormalizeDefinition(definition *ast.Document, report *operationreport.Report) {
	normalizer := NewDefinitionNormalizer()
	normalizer.NormalizeDefinition(definition, report)
}

// DefinitionNormalizer walks a given AST and applies all registered rules
type DefinitionNormalizer struct {
	walker *astvisitor.Walker
}

// NewDefinitionNormalizer creates a new DefinitionNormalizer and sets up all default rules
func NewDefinitionNormalizer() *DefinitionNormalizer {
	normalizer := &DefinitionNormalizer{}
	normalizer.setupWalkers()
	return normalizer
}

func (o *DefinitionNormalizer) setupWalkers() {
	walker := astvisitor.NewWalker(48)

	extendObjectTypeDefinition(&walker)
	extendInputObjectTypeDefinition(&walker)
	extendEnumTypeDefinition(&walker)
	extendInterfaceTypeDefinition(&walker)
	extendScalarTypeDefinition(&walker)
	extendUnionTypeDefinition(&walker)
	removeMergedTypeExtensions(&walker)
	implicitSchemaDefinition(&walker)

	o.walker = &walker
}

// NormalizeDefinition applies all registered rules to the AST
func (o *DefinitionNormalizer) NormalizeDefinition(definition *ast.Document, report *operationreport.Report) {
	o.walker.Walk(definition, nil, report)
}
