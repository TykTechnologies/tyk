package swagger

import "github.com/swaggest/openapi-go/openapi3"

var Tags []openapi3.Tag

func addTag(name, description string) {
	Tags = append(Tags, openapi3.Tag{
		Name:        name,
		Description: stringPointerValue(description),
	})
}
