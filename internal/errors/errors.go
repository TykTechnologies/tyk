package errors

import "strings"

func Formatter(errs []error) string {
	var result strings.Builder
	for i, err := range errs {
		result.WriteString(err.Error())
		if i < len(errs)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}
