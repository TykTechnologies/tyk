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
	ErrorByIndex(i int) error
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

func (o OperationValidationErrors) ErrorByIndex(i int) error {
	if i >= o.Count() {
		return nil
	}

	return o[i]
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

func schemaValidationErrorsFromOperationReport(report operationreport.Report) (errors SchemaValidationErrors) {
	if len(report.ExternalErrors) == 0 {
		return nil
	}

	for _, externalError := range report.ExternalErrors {
		validationError := SchemaValidationError{
			Message: externalError.Message,
		}

		errors = append(errors, validationError)
	}

	return errors
}

func (s SchemaValidationErrors) Error() string {
	return fmt.Sprintf("schema contains %d error(s)", s.Count())
}

func (s SchemaValidationErrors) WriteResponse(writer io.Writer) (n int, err error) {
	return writer.Write(nil)
}

func (s SchemaValidationErrors) Count() int {
	return len(s)
}

func (s SchemaValidationErrors) ErrorByIndex(i int) error {
	if i >= s.Count() {
		return nil
	}
	return s[i]
}

type SchemaValidationError struct {
	Message string `json:"message"`
}

func (s SchemaValidationError) Error() string {
	return s.Message
}

type ErrorPath []interface{}

type ErrorLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}
