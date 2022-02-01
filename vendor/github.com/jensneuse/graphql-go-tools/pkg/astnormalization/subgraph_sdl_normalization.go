package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

func NormalizeSubgraphSDL(definition *ast.Document, report *operationreport.Report) {
	normalizer := NewSubgraphSDLNormalizer()
	normalizer.NormalizeSubgraphSDL(definition, report)
}

type SubgraphSDLNormalizer struct {
	walker *astvisitor.Walker
}

func NewSubgraphSDLNormalizer() *SubgraphSDLNormalizer {
	normalizer := &SubgraphSDLNormalizer{}
	normalizer.setupWalkers()
	return normalizer
}

func (s *SubgraphSDLNormalizer) setupWalkers() {
	walker := astvisitor.NewWalker(48)
	implicitExtendRootOperation(&walker)
	extendsDirective(&walker)
	s.walker = &walker
}

func (s *SubgraphSDLNormalizer) NormalizeSubgraphSDL(definition *ast.Document, report *operationreport.Report) {
	s.walker.Walk(definition, nil, report)
}
