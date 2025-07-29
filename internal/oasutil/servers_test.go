package oasutil_test

import (
	"github.com/TykTechnologies/kin-openapi/openapi3"
	"github.com/TykTechnologies/tyk/internal/oasutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseServerUrl(t *testing.T) {
	t.Run("positive test cases", func(t *testing.T) {
		type testCase struct {
			name     string
			input    string
			expected *oasutil.ServerUrl
		}

		for _, tCase := range []testCase{
			{"simple test case", "example.com", &oasutil.ServerUrl{
				Url:           "example.com",
				UrlNormalized: "example.com",
			}},
			{"complex test case", "https://{subdomain:[a-z]+}.example.com/{version:v[0-9]+}", &oasutil.ServerUrl{
				Url:           "https://{subdomain:[a-z]+}.example.com/{version:v[0-9]+}",
				UrlNormalized: "https://{subdomain}.example.com/{version}",
				Variables: map[string]*openapi3.ServerVariable{
					"subdomain": {
						Default: oasutil.DefaultServerUrlPrefix + "1",
					},
					"version": {
						Default: oasutil.DefaultServerUrlPrefix + "2",
					},
				},
			}},
			{"accepts routes without patterns", "https://{subdomain}.example.com/{version}", &oasutil.ServerUrl{
				Url:           "https://{subdomain}.example.com/{version}",
				UrlNormalized: "https://{subdomain}.example.com/{version}",
				Variables: map[string]*openapi3.ServerVariable{
					"subdomain": {
						Default: oasutil.DefaultServerUrlPrefix + "1",
					},
					"version": {
						Default: oasutil.DefaultServerUrlPrefix + "2",
					},
				},
			}},
			{"one letter variable", "https://example.com/{v}/", &oasutil.ServerUrl{
				Url:           "https://example.com/{v}/",
				UrlNormalized: "https://example.com/{v}/",
				Variables: map[string]*openapi3.ServerVariable{
					"v": {
						Default: oasutil.DefaultServerUrlPrefix + "1",
					},
				},
			}},
			{"parses empty line", "", &oasutil.ServerUrl{
				Url:           "",
				UrlNormalized: "",
				Variables:     nil,
			}},
		} {
			t.Run(tCase.name, func(t *testing.T) {
				res, err := oasutil.ParseServerUrl(tCase.input)
				assert.NoError(t, err)
				assert.Equal(t, tCase.expected, res)
			})
		}
	})

	t.Run("error test cases", func(t *testing.T) {
		type testCase struct {
			name        string
			input       string
			expectedErr error
		}

		for _, tCase := range []testCase{
			{"unexpected curly brace 1", "}example.com", oasutil.ErrUnexpectedCurlyBrace},
			{"unexpected curly brace 2", "example}.com", oasutil.ErrUnexpectedCurlyBrace},
			{"empty variable name", "example{}.com", oasutil.ErrEmptyVariableName},
			{"empty variable name 2", "example{:[a-z]+}.com", oasutil.ErrEmptyVariableName},
			{"no closed brace", "{example.com", oasutil.ErrParse},
			{"server variable collision", "{version:[a-z]+}.example.com/{version:[0-9]+}", oasutil.ErrVariableCollision},
		} {
			t.Run(tCase.name, func(t *testing.T) {
				_, err := oasutil.ParseServerUrl(tCase.input)
				assert.ErrorContains(t, err, tCase.expectedErr.Error())
			})
		}
	})
}
