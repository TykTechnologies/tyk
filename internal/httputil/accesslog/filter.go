package accesslog

import (
	"github.com/sirupsen/logrus"
)

// Filter filters the input logrus fields and retains only the allowed fields.
// The function is case sensitive so keys have to match the case exactly.
func Filter(in logrus.Fields, allowedFields []string) logrus.Fields {
	if len(allowedFields) == 0 {
		return in
	}

	// Create a map to quickly check if a field is allowed.
	allowed := make(map[string]struct{}, len(allowedFields))
	for _, field := range allowedFields {
		allowed[field] = struct{}{}
	}

	result := make(logrus.Fields, len(allowedFields))

	// Add the "prefix" field by default, if it exists in the input
	if prefix, exists := in["prefix"]; exists {
		result["prefix"] = prefix
	}

	// Filter keys based on config
	for key, value := range in {
		if _, exists := allowed[key]; exists {
			result[key] = value
		}
	}

	return result
}
