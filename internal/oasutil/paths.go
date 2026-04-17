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

// Keep the unexported alias for backward compatibility within this package.
var pathParamRegex = PathParamRegex

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
