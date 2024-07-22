package oasutil

import (
	"regexp"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

type PathItem struct {
	Item  *openapi3.PathItem
	Value string
}

var pathParamRegex = regexp.MustCompile(`\{[^}]+\}`)

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
			Item:  in[v],
			Value: v,
		}
		result = append(result, value)
	}

	return result
}
