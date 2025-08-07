package pathutil

import (
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/samber/lo"
)

// Normalize responsible for merging regex path with non regex and generation oas-valid path in output
func Normalize(in *openapi3.Paths) (*openapi3.Paths, error) {
	if in == nil {
		return nil, nil
	}

	norm, err := newNormalizer(*in)

	if err != nil {
		return nil, err
	}

	normalized, err := norm.normalize()

	if err != nil {
		return nil, err
	}

	return normalized, nil
}

func Matches(sample, pattern string, parameters openapi3.Parameters) (bool, error) {
	parsedSample, err := parsePath(sample)
	if err != nil {
		return false, err
	}

	parsedPattern, err := parsePath(pattern)
	if err != nil {
		return false, err
	}

	return matches(parsedSample, parsedPattern, parameters), nil
}

func matches(sample, pattern *Path, parameters openapi3.Parameters) bool {
	if len(sample.parts) != len(pattern.parts) {
		return false
	}

	for i, samplePart := range sample.parts {
		if !matchPart(samplePart, pattern.parts[i], parameters) {
			return false
		}
	}

	return true
}

type normalizer struct {
	normalized    *openapi3.Paths
	nonNormalized *openapi3.Paths
}

func newNormalizer(in openapi3.Paths) (*normalizer, error) {
	normalized := openapi3.NewPaths()
	nonNormalized := openapi3.NewPaths()

	for path, op := range in.Map() {
		parsed, err := parsePath(path)

		if err != nil {
			return nil, err
		}

		if parsed.HasReParams() {
			nonNormalized.Set(path, reflect.Clone(op))
		} else {
			normalized.Set(path, reflect.Clone(op))
		}
	}

	return &normalizer{
		normalized:    normalized,
		nonNormalized: nonNormalized,
	}, nil
}

func (n *normalizer) normalize() (*openapi3.Paths, error) {
	normalized := reflect.Clone(n.normalized)

	for path, pathItem := range n.nonNormalized.Map() {
		matched, err := getMatches(normalized, path)

		if err != nil {
			return nil, err
		}

		if len(matched) > 0 {
			mergeAll(pathItem, matched)
		} else if parsedPath, err := parsePath(path); err != nil {
			return nil, err
		} else {
			clonedPathItems := reflect.Clone(pathItem)
			parsedPath.PropagateTo(clonedPathItems.Parameters)

			normalized.Set(
				parsedPath.path,
				clonedPathItems,
			)
		}
	}

	return normalized, nil
}

func getMatches(source *openapi3.Paths, sample string) ([]*openapi3.PathItem, error) {
	var matched []*openapi3.PathItem

	for pattern, pathItem := range source.Map() {
		if ok, err := Matches(sample, pattern, pathItem.Parameters); err != nil {
			return nil, err
		} else if ok {
			matched = append(matched, pathItem)
		}
	}

	return matched, nil
}

func matchPart(sample, pattern pathPart, parameters openapi3.Parameters) bool {
	switch {
	case sample.isSplitter() && pattern.isSplitter():
		return true
	case sample.isPartRaw() && pattern.isPartRaw():
		return sample.name == pattern.name
	case sample.isRegExp() && pattern.isParameter():
		param, ok := lo.Find(parameters, func(item *openapi3.ParameterRef) bool {
			if item.Value == nil || item.Value.Schema == nil || item.Value.Schema.Value == nil {
				return false
			}

			return item.Value.Schema.Value.Type.Includes(openapi3.TypeString) && item.Value.Name == pattern.name
		})

		if !ok {
			return false
		}

		return param.Value.Schema.Value.Pattern == sample.pattern
	}

	return false
}

func mergeAll(src *openapi3.PathItem, matches []*openapi3.PathItem) {
	for _, matchedPathItem := range matches {
		mergeOne(src, matchedPathItem)
	}
}

func mergeOne(src, dest *openapi3.PathItem) {
	for method, op := range src.Operations() {
		// todo: what should I do with parameters names (they could differ)
		// currently operations are just replacing each other but in future more sophisticated merge strategy can be used here
		// should I drop not provided strategies?
		dest.SetOperation(method, reflect.Clone(op))
	}
}
