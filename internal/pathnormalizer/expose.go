package pathnormalizer

import (
	logger "github.com/TykTechnologies/tyk/log"
	"github.com/getkin/kin-openapi/openapi3"
)

var (
	log = logger.Get()
)

// Validate validates paths keys can be normalized from user-defined keys to proper ones.
func Validate(paths *openapi3.Paths) error {
	_, err := Normalize(paths)
	return err
}

// Normalize creates normalized paths from input
func Normalize(paths *openapi3.Paths) (*openapi3.Paths, error) {
	mapper, err := NewMapper(paths)

	if err != nil {
		return nil, err
	}

	return mapper.getNormalized(), nil
}
