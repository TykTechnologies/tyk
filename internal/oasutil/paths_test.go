package oasutil

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestSortByPathLength(t *testing.T) {
	paths := openapi3.Paths{
		"/test/a":       nil,
		"/test/b":       nil,
		"/test/c":       nil,
		"/test/sub1":    nil,
		"/test/sub{id}": nil,
		"/test/sub2":    nil,
		"/test":         nil,
		"/test/{id}":    nil,
	}

	out := SortByPathLength(paths)

	got := []string{}
	for _, v := range out {
		got = append(got, v.Value)
	}

	want := []string{
		"/test/sub1",
		"/test/sub2",
		"/test/sub{id}",
		"/test/a",
		"/test/b",
		"/test/c",
		"/test/{id}",
		"/test",
	}

	assert.Equal(t, want, got)

}
