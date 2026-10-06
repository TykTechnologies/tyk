package test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRequestContentType(t *testing.T) {
	tests := []struct {
		name    string
		caseDef TestCase
		want    []string
	}{
		{name: "default", caseDef: TestCase{Method: http.MethodPost, Path: "/"}, want: []string{"application/json"}},
		{name: "explicit", caseDef: TestCase{Method: http.MethodPost, Path: "/", Headers: map[string]string{"Content-Type": "text/plain"}}, want: []string{"text/plain"}},
		{name: "duplicates remain explicit", caseDef: TestCase{Method: http.MethodPost, Path: "/", HeadersArray: map[string][]string{"Content-Type": {"application/json", "text/plain"}}}, want: []string{"application/json", "text/plain"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewRequest(&test.caseDef)
			require.NoError(t, err)
			require.Equal(t, test.want, request.Header.Values("Content-Type"))
		})
	}
}
