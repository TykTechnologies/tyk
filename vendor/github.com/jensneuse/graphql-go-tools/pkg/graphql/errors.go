package graphql

import (
	"io"
)

type OperationValidationErrors []OperationValidationError

func (v OperationValidationErrors) AsGraphQLErrors(writer io.Writer) (n int, err error) {
	return writer.Write(nil)
}

type OperationValidationError struct {
}

func (v OperationValidationError) Error() string {
	return ""
}

type SchemaValidationErrors []SchemaValidationError

type SchemaValidationError struct {
}

func (s SchemaValidationError) Error() string {
	return ""
}
