package oasutil

import (
	"regexp"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

// PathItem holds the path to a particular OAS path item.
type PathItem struct {
	// PathItem represents an openapi3.Paths value.
	*openapi3.PathItem

	// Path is an openapi3.Paths key, the endpoint URL.
	Path string
}

var pathParamRegex = regexp.MustCompile(`\{[^}]+\}`)

// SortByPathLength decomposes an openapi3.Paths to a sorted []PathItem.
// The sorting takes the length of the paths into account, as well as
// path parameters, sorting them by length descending, and ordering
// path parameters after the statically defined paths.
//
// Check the test function for sorting expectations.
func SortByPathLength(in openapi3.Paths) []PathItem {
	// get urls
	paths := []string{}
	for k := range in {
		paths = append(paths, k)
	}

	// sort by length and lexicographically
	sort.Slice(paths, func(i, j int) bool {
		pathI := pathParamRegex.ReplaceAllString(paths[i], "")
		pathJ := pathParamRegex.ReplaceAllString(paths[j], "")

		il, jl := len(pathI), len(pathJ)
		if il == jl {
			return pathI < pathJ
		}
		return il > jl
	})

	// collect url and pathItem
	result := []PathItem{}
	for _, v := range paths {
		value := PathItem{
			PathItem: in[v],
			Path:     v,
		}
		result = append(result, value)
	}

	return result
}
