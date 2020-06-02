package graphql

import (
	"fmt"
	"io"

	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

type Errors interface {
	error
	WriteResponse(writer io.Writer) (n int, err error)
	Count() int
}

type OperationValidationErrors []OperationValidationError

func operationValidationErrorsFromOperationReport(report operationreport.Report) (errors OperationValidationErrors) {
	if len(report.ExternalErrors) == 0 {
		return nil
	}

	for _, externalError := range report.ExternalErrors {
		validationError := OperationValidationError{
			Message: externalError.Message,
			// TODO: add path
			// TODO: add location
		}

		errors = append(errors, validationError)
	}

	return errors
}

func (o OperationValidationErrors) Error() string {
	return fmt.Sprintf("operation contains %d error(s)", len(o))
}

func (o OperationValidationErrors) WriteResponse(writer io.Writer) (n int, err error) {
	response := Response{
		Errors: o,
	}

	responseBytes, err := response.Marshal()
	if err != nil {
		return 0, err
	}

	return writer.Write(responseBytes)
}

func (o OperationValidationErrors) Count() int {
	return len(o)
}

type OperationValidationError struct {
	Message   string          `json:"message"`
	Locations []ErrorLocation `json:"locations,omitempty"`
	Path      ErrorPath       `json:"path,omitempty"`
}

func (o OperationValidationError) Error() string {
	return o.Message
}

type SchemaValidationErrors []SchemaValidationError

func (s SchemaValidationErrors) Error() string {
	return ""
}

func (s SchemaValidationErrors) WriteResponse(writer io.Writer) (n int, err error) {
	return writer.Write(nil)
}

func (s SchemaValidationErrors) Count() int {
	return len(s)
}

type SchemaValidationError struct {
}

func (s SchemaValidationError) Error() string {
	return ""
}

type ErrorPath []interface{}

type ErrorLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}
