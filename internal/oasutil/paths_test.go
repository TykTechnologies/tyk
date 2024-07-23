package oasutil

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

var testPathsForSorting = openapi3.Paths{
	"/test/a":           nil,
	"/test/b":           nil,
	"/test/c":           nil,
	"/test/{id}/asset":  nil,
	"/test/{id}/{file}": nil,
	"/test/sub":         nil,
	"/test/sub1":        nil,
	"/test/sub{id}":     nil,
	"/test/sub2":        nil,
	"/test":             nil,
	"/test/{id}":        nil,
}

// TestSortByPathLength tests our custom sorting for the OAS paths.
func TestSortByPathLength(t *testing.T) {
	paths := testPathsForSorting

	out := SortByPathLength(paths)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	want := []string{
		"/test/{id}/asset",
		"/test/{id}/{file}",
		"/test/sub1",
		"/test/sub2",
		"/test/sub",
		"/test/sub{id}",
		"/test/a",
		"/test/b",
		"/test/c",
		"/test/{id}",
		"/test",
	}

	assert.Equal(t, want, got)
}

// TestExtractPath uses the upstream library to extract an ordered list of paths.
func TestExtractPaths(t *testing.T) {
	paths := testPathsForSorting
	order := paths.InMatchingOrder()

	out := ExtractPaths(paths, order)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	want := []string{
		"/test/sub2",
		"/test/sub1",
		"/test/sub",
		"/test/c",
		"/test/b",
		"/test/a",
		"/test",
		"/test/{id}/asset",
		"/test/{id}",
		"/test/sub{id}", // this is problematic, should be one line up
		"/test/{id}/{file}",
	}

	assert.Equal(t, want, got)
}
