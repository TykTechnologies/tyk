package oasutil

import (
	"testing"

	"github.com/TykTechnologies/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func testOASPaths(paths []string) openapi3.Paths {
	result := openapi3.Paths{}
	for _, p := range paths {
		result[p] = nil
	}
	return result
}

// TestSortByPathLength tests our custom sorting for the OAS paths.
func TestSortByPathLength(t *testing.T) {
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

	want = []string{
		"/test/abc/def",
		"/anything/dupa",
		"/anything/{id}",
		"/test/abc",
		"/test/{id}",
		"/anything",
		"/test",
	}

	paths := testOASPaths(want)

	out := SortByPathLength(paths)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	assert.Equal(t, want, got, "got %#v", got)
}

// TestExtractPath uses the upstream library to extract an ordered list of paths.
func TestExtractPaths(t *testing.T) {
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

	paths := testOASPaths(want)

	order := paths.InMatchingOrder()

	out := ExtractPaths(paths, order)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Path)
	}

	assert.Equal(t, want, got)
}
