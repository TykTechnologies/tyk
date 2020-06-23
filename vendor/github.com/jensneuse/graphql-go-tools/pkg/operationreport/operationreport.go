// Package operationreport helps generating the errors object for a GraphQL Operation.
package operationreport

import "fmt"

type Report struct {
	InternalErrors []error
	ExternalErrors []ExternalError
}

func (r Report) Error() string {
	out := ""
	for i := range r.InternalErrors {
		if i != 0 {
			out += "\n"
		}
		out += fmt.Sprintf("internal: %s", r.InternalErrors[i].Error())
	}
	for i := range r.ExternalErrors {
		if i != 0 {
			out += "\n"
		}
		out += fmt.Sprintf("external: %s, locations: %+v, path: %v", r.ExternalErrors[i].Message, r.ExternalErrors[i].Locations, r.ExternalErrors[i].Path)
	}
	return out
}

func (r *Report) HasErrors() bool {
	return len(r.InternalErrors) > 0 || len(r.ExternalErrors) > 0
}

func (r *Report) Reset() {
	r.InternalErrors = r.InternalErrors[:0]
	r.ExternalErrors = r.ExternalErrors[:0]
}

func (r *Report) AddInternalError(err error) {
	r.InternalErrors = append(r.InternalErrors, err)
}

func (r *Report) AddExternalError(gqlError ExternalError) {
	r.ExternalErrors = append(r.ExternalErrors, gqlError)
}
