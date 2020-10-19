/*
	package operation_complexity implements two common algorithms used by GitHub to calculate GraphQL query complexity

	1. Node count, the maximum number of Nodes a query may return
	2. Complexity, the maximum number of Node requests that might be needed to execute the query

	OperationComplexityEstimator takes a schema definition and a query and then walks recursively through the query to calculate both variables.

	The calculation can be influenced by integer arguments on fields that indicate the amount of Nodes returned by a field.

	To help the algorithm understand your schema you could make use of these two directives:

	- directive @nodeCountMultiply on ARGUMENT_DEFINITION
	- directive @nodeCountSkip on FIELD

	nodeCountMultiply:
	Indicates that the Int value the directive is applied on should be used as a Node multiplier

	nodeCountSkip:
	Indicates that the algorithm should skip this Node. This is useful to whitelist certain query paths, e.g. for introspection.
*/
package operation_complexity

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type OperationStats struct {
	NodeCount  int
	Complexity int
	Depth      int
}

type RootFieldStats struct {
	TypeName  string
	FieldName string
	Alias     string
	Stats     OperationStats
}

var (
	nodeCountMultiply = []byte("nodeCountMultiply")
	nodeCountSkip     = []byte("nodeCountSkip")
)

type OperationComplexityEstimator struct {
	walker  *astvisitor.Walker
	visitor *complexityVisitor
}

func NewOperationComplexityEstimator() *OperationComplexityEstimator {

	walker := astvisitor.NewWalker(48)
	visitor := &complexityVisitor{
		Walker:      &walker,
		multipliers: make([]multiplier, 0, 16),
	}

	walker.RegisterEnterDocumentVisitor(visitor)
	walker.RegisterEnterArgumentVisitor(visitor)
	walker.RegisterLeaveFieldVisitor(visitor)
	walker.RegisterEnterFieldVisitor(visitor)
	walker.RegisterEnterSelectionSetVisitor(visitor)
	walker.RegisterEnterFragmentDefinitionVisitor(visitor)

	return &OperationComplexityEstimator{
		walker:  &walker,
		visitor: visitor,
	}
}

func (n *OperationComplexityEstimator) Do(operation, definition *ast.Document, report *operationreport.Report) (OperationStats, []RootFieldStats) {
	n.visitor.count = 0
	n.visitor.complexity = 0
	n.visitor.maxFieldDepth = 0
	n.visitor.multipliers = n.visitor.multipliers[:0]

	n.visitor.maxSelectionSetFieldDepth = 0
	n.visitor.selectionSetDepth = 0

	if n.visitor.calculatedRootFieldStats == nil {
		n.visitor.calculatedRootFieldStats = make([]RootFieldStats, 0, len(definition.RootOperationTypeDefinitions))
	}
	n.visitor.calculatedRootFieldStats = n.visitor.calculatedRootFieldStats[:0]

	if n.visitor.rootOperationTypeNames == nil {
		n.visitor.rootOperationTypeNames = make(map[string]struct{}, len(definition.RootOperationTypeDefinitions))
	}
	for key := range n.visitor.rootOperationTypeNames {
		delete(n.visitor.rootOperationTypeNames, key)
	}

	n.walker.Walk(operation, definition, report)

	depth := n.visitor.maxFieldDepth - n.visitor.selectionSetDepth
	globalResult := OperationStats{
		NodeCount:  n.visitor.count,
		Complexity: n.visitor.complexity,
		Depth:      depth,
	}

	return globalResult, n.visitor.calculatedRootFieldStats
}

func CalculateOperationComplexity(operation, definition *ast.Document, report *operationreport.Report) (OperationStats, []RootFieldStats) {
	estimator := NewOperationComplexityEstimator()
	return estimator.Do(operation, definition, report)
}

type complexityVisitor struct {
	*astvisitor.Walker
	operation, definition *ast.Document
	count                 int
	complexity            int
	maxFieldDepth         int
	multipliers           []multiplier

	maxSelectionSetFieldDepth int
	selectionSetDepth         int

	rootOperationTypeNames map[string]struct{}

	currentRootFieldStats                RootFieldStats
	currentRootFieldMaxDepth             int
	currentRootFieldMaxSelectionSetDepth int
	currentRootFieldSelectionSetDepth    int

	calculatedRootFieldStats []RootFieldStats
}

type multiplier struct {
	fieldRef int
	multi    int
}

func (c *complexityVisitor) calculateMultiplied(i int) int {
	for _, j := range c.multipliers {
		i = i * j.multi
	}
	return i
}

func (c *complexityVisitor) EnterDocument(operation, definition *ast.Document) {
	c.operation = operation
	c.definition = definition

	for i := 0; i < len(c.definition.RootOperationTypeDefinitions); i++ {
		name := c.definition.Input.ByteSliceString(c.definition.RootOperationTypeDefinitions[i].NamedType.Name)
		c.rootOperationTypeNames[name] = struct{}{}
	}
}

func (c *complexityVisitor) EnterArgument(ref int) {

	if c.Ancestors[len(c.Ancestors)-1].Kind != ast.NodeKindField {
		return
	}

	definition, ok := c.ArgumentInputValueDefinition(ref)
	if !ok {
		return
	}

	if !c.definition.InputValueDefinitionHasDirective(definition, nodeCountMultiply) {
		return
	}

	value := c.operation.ArgumentValue(ref)
	if value.Kind == ast.ValueKindInteger {
		multi := c.operation.IntValueAsInt(value.Ref)
		c.multipliers = append(c.multipliers, multiplier{
			fieldRef: c.Ancestors[len(c.Ancestors)-1].Ref,
			multi:    int(multi),
		})
	}
}

func (c *complexityVisitor) EnterField(ref int) {
	definition, exists := c.FieldDefinition(ref)
	if !exists {
		return
	}

	if _, exits := c.definition.FieldDefinitionDirectiveByName(definition, nodeCountSkip); exits {
		c.SkipNode()
		return
	}

	typeName, fieldName, alias := c.extractFieldRelatedNames(ref, definition)
	if c.isRootType(typeName) {
		c.resetCurrentRootFieldComplexity(typeName, fieldName, alias)
	}

	if !c.operation.FieldHasSelections(ref) {
		return
	}

	c.complexity = c.complexity + c.calculateMultiplied(1)
	if c.Depth > c.maxFieldDepth {
		c.maxFieldDepth = c.Depth
	}

	c.currentRootFieldStats.Stats.Complexity = c.currentRootFieldStats.Stats.Complexity + c.calculateMultiplied(1)
	if c.Depth > c.currentRootFieldMaxDepth {
		c.currentRootFieldMaxDepth = c.Depth
	}
}

func (c *complexityVisitor) LeaveField(ref int) {
	if c.isRootTypeField() {
		c.endRootFieldComplexityCalculation()
	}

	if len(c.multipliers) == 0 {
		return
	}

	if c.multipliers[len(c.multipliers)-1].fieldRef == ref {
		c.multipliers = c.multipliers[:len(c.multipliers)-1]
	}
}

func (c *complexityVisitor) EnterSelectionSet(ref int) {

	if c.Ancestors[len(c.Ancestors)-1].Kind != ast.NodeKindField {
		return
	}

	c.count = c.count + c.calculateMultiplied(1)
	if c.Depth > c.maxSelectionSetFieldDepth {
		c.maxSelectionSetFieldDepth = c.Depth
		c.selectionSetDepth++
	}

	c.currentRootFieldStats.Stats.NodeCount = c.currentRootFieldStats.Stats.NodeCount + c.calculateMultiplied(1)
	if c.Depth > c.currentRootFieldMaxSelectionSetDepth {
		c.currentRootFieldMaxSelectionSetDepth = c.Depth
		c.currentRootFieldSelectionSetDepth++
	}
}

func (c *complexityVisitor) EnterFragmentDefinition(ref int) {
	c.SkipNode()
}

func (c *complexityVisitor) resetCurrentRootFieldComplexity(typeName, fieldName, alias string) {
	c.currentRootFieldStats = RootFieldStats{
		TypeName:  typeName,
		FieldName: fieldName,
		Alias:     alias,
		Stats: OperationStats{
			NodeCount:  0,
			Complexity: 0,
			Depth:      0,
		},
	}
}

func (c *complexityVisitor) endRootFieldComplexityCalculation() {
	currentDepth := c.currentRootFieldMaxDepth - c.currentRootFieldSelectionSetDepth
	if currentDepth > 0 {
		currentDepth--
	}
	c.currentRootFieldStats.Stats.Depth = currentDepth
	c.calculatedRootFieldStats = append(c.calculatedRootFieldStats, c.currentRootFieldStats)

	c.currentRootFieldMaxDepth = 0
	c.currentRootFieldMaxSelectionSetDepth = 0
	c.currentRootFieldSelectionSetDepth = 0
}

func (c *complexityVisitor) extractFieldRelatedNames(ref, definitionRef int) (typeName, fieldName, alias string) {
	fieldName = c.definition.FieldDefinitionNameString(definitionRef)
	alias = c.operation.FieldAliasOrNameString(ref)
	if fieldName == alias {
		alias = ""
	}

	return c.EnclosingTypeDefinition.Name(c.definition), fieldName, alias
}

func (c *complexityVisitor) isRootType(name string) bool {
	_, ok := c.rootOperationTypeNames[name]
	return ok
}

func (c *complexityVisitor) isRootTypeField() bool {
	enclosingTypeName := c.EnclosingTypeDefinition.Name(c.definition)
	return c.isRootType(enclosingTypeName)
}
