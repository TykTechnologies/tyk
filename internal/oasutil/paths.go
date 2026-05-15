package oasutil

import (
	"regexp"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// PathItem holds the path to a particular OAS path item.
type PathItem struct {
	// PathItem represents an openapi3.Paths value.
	*openapi3.PathItem

	// Path is an openapi3.Paths key, the endpoint URL.
	Path string
}

// PathParamRegex matches path parameters like {id} or {employeeId} in OAS paths.
var PathParamRegex = regexp.MustCompile(`\{[^}]+\}`)

// ExtractPaths will extract paths with the given order.
func ExtractPaths(in openapi3.Paths, order []string) []PathItem {
	// collect url and pathItem
	result := []PathItem{}
	pathsMap := in.Map()
	for _, v := range order {
		value := PathItem{
			PathItem: pathsMap[v],
			Path:     v,
		}
		result = append(result, value)
	}

	return result
}

// PathLess reports whether pathA should sort before pathB using the
// standard Tyk path priority rules:
//   - Strip path parameters {…} before comparing
//   - If two paths are equal after stripping, the non-parameterised one goes first
//   - Sort by number of "/" segments (more segments first)
//   - Sort by string length (longer first)
//   - Alphabetical for equal length
func PathLess(pathA, pathB string) bool {
	a := PathParamRegex.ReplaceAllString(pathA, "")
	b := PathParamRegex.ReplaceAllString(pathB, "")

	// handle /sub and /sub{id} order with raw path.
	if a == b {
		// we're reversing paths here so path with
		// parameter is sorted after the literal.
		a, b = pathB, pathA
	}

	// sort by number of path fragments
	ka, kb := strings.Count(a, "/"), strings.Count(b, "/")
	if ka != kb {
		return ka > kb
	}

	la, lb := len(a), len(b)
	if la == lb {
		return a < b
	}
	return la > lb
}

// SortByPathLength decomposes an openapi3.Paths to a sorted []PathItem.
// The sorting takes the length of the paths into account, as well as
// path parameters, sorting them by length descending, and ordering
// path parameters after the statically defined paths.
//
// Check the test function for sorting expectations.
func SortByPathLength(in openapi3.Paths) []PathItem {
	// get urls
	paths := []string{}
	pathsMap := in.Map()
	for k := range pathsMap {
		paths = append(paths, k)
	}

	sort.Slice(paths, func(i, j int) bool {
		return PathLess(paths[i], paths[j])
	})

	return ExtractPaths(in, paths)
}

func PathToRegex(path string, params openapi3.Parameters) string {
	varRegex := regexp.MustCompile(`\{([^}]+)\}`)

	regexPath := varRegex.ReplaceAllStringFunc(path, func(match string) string {
		paramName := match[1 : len(match)-1]
		paramType, explicitPattern := GetParamDetails(params, paramName)

		var pattern string
		if explicitPattern != "" {
			pattern = strings.TrimPrefix(explicitPattern, "^")
			pattern = strings.TrimSuffix(pattern, "$")
		} else {
			pattern = getRegexPatternForType(paramType)
		}

		return pattern
	})

	return regexPath
}

func GetParamDetails(params openapi3.Parameters, paramName string) (string, string) {
	for _, paramRef := range params {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}

		if paramRef.Value.Name == paramName {
			if paramRef.Value.Schema != nil && paramRef.Value.Schema.Value != nil {
				schema := paramRef.Value.Schema.Value
				var paramType string
				if schema.Type != nil && len(*schema.Type) > 0 {
					paramType = (*schema.Type)[0]
				}
				return paramType, schema.Pattern
			}

			if paramRef.Value.Content != nil {
				for _, mediaType := range paramRef.Value.Content {
					if mediaType.Schema != nil && mediaType.Schema.Value != nil {
						schema := mediaType.Schema.Value
						var paramType string
						if schema.Type != nil && len(*schema.Type) > 0 {
							paramType = (*schema.Type)[0]
						}
						return paramType, schema.Pattern
					}
				}
			}
		}
	}
	return "", ""
}

func getRegexPatternForType(paramType string) string {
	switch paramType {
	case "integer":
		return `[-+]?\d+`
	case "number":
		return `[-+]?[0-9]*\.?[0-9]+`
	case "boolean":
		return `(?:true|false)`
	case "string":
		return `[^/]+`
	default:
		return `[^/]+`
	}
}
