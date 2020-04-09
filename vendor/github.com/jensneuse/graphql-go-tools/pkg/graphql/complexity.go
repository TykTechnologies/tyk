package graphql

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/middleware/operation_complexity"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

var DefaultComplexityCalculator = defaultComplexityCalculator{}

type ComplexityCalculator interface {
	Calculate(operation, definition *ast.Document) (ComplexityResult, error)
}

type defaultComplexityCalculator struct {
}

func (d defaultComplexityCalculator) Calculate(operation, definition *ast.Document) (ComplexityResult, error) {
	report := operationreport.Report{}
	nodeCount, complexity, depth := operation_complexity.CalculateOperationComplexity(operation, definition, &report)

	return complexityResult(nodeCount, complexity, depth, report)
}

type ComplexityResult struct {
	NodeCount  int
	Complexity int
	Depth      int
	Errors     Errors
}

func complexityResult(nodeCount, complexity, depth int, report operationreport.Report) (ComplexityResult, error) {
	result := ComplexityResult{
		NodeCount:  nodeCount,
		Complexity: complexity,
		Depth:      depth,
		Errors:     nil,
	}

	if !report.HasErrors() {
		return result, nil
	}

	result.Errors = operationValidationErrorsFromOperationReport(report)

	var err error
	if len(report.InternalErrors) > 0 {
		err = report.InternalErrors[0]
	}

	return result, err
}
