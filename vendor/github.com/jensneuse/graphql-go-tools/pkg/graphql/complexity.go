package graphql

var DefaultComplexityCalulator = DefaultComplexityCalculator{}

type ComplexityCalculator interface {
	Calculate(schema *Schema, request *Request) int
}

type DefaultComplexityCalculator struct {
}

func (d DefaultComplexityCalculator) Calculate(schema *Schema, request *Request) int {
	return 1
}
