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
	globalComplexityResult, fieldsComplexityResult := operation_complexity.CalculateOperationComplexity(operation, definition, &report)

	return complexityResult(globalComplexityResult, fieldsComplexityResult, report)
}

type ComplexityResult struct {
	NodeCount    int
	Complexity   int
	Depth        int
	PerRootField []FieldComplexityResult
	Errors       Errors
}

type FieldComplexityResult struct {
	TypeName   string
	FieldName  string
	Alias      string
	NodeCount  int
	Complexity int
	Depth      int
}

func complexityResult(globalComplexityResult operation_complexity.OperationStats, fieldsComplexityResult []operation_complexity.RootFieldStats, report operationreport.Report) (ComplexityResult, error) {
	allFieldComplexityResults := make([]FieldComplexityResult, 0, len(fieldsComplexityResult))
	for _, fieldResult := range fieldsComplexityResult {
		allFieldComplexityResults = append(allFieldComplexityResults, FieldComplexityResult{
			TypeName:   fieldResult.TypeName,
			FieldName:  fieldResult.FieldName,
			Alias:      fieldResult.Alias,
			NodeCount:  fieldResult.Stats.NodeCount,
			Complexity: fieldResult.Stats.Complexity,
			Depth:      fieldResult.Stats.Depth,
		})
	}

	result := ComplexityResult{
		NodeCount:    globalComplexityResult.NodeCount,
		Complexity:   globalComplexityResult.Complexity,
		Depth:        globalComplexityResult.Depth,
		PerRootField: allFieldComplexityResults,
		Errors:       nil,
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
