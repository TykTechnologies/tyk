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

var pathParamRegex = regexp.MustCompile(`\{[^}]+\}`)

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

	// sort by length and lexicographically
	sort.Slice(paths, func(i, j int) bool {
		pathI := pathParamRegex.ReplaceAllString(paths[i], "")
		pathJ := pathParamRegex.ReplaceAllString(paths[j], "")

		// handle /sub and /sub{id} order with raw path.
		if pathI == pathJ {
			// we're reversing indexes here so path with
			// parameter is sorted after the literal.
			pathI, pathJ = paths[j], paths[i]
		}

		// sort by number of path fragments
		k, v := strings.Count(pathI, "/"), strings.Count(pathJ, "/")
		if k != v {
			return k > v
		}

		il, jl := len(pathI), len(pathJ)
		if il == jl {
			return pathI < pathJ
		}
		return il > jl
	})

	return ExtractPaths(in, paths)
}
