package gateway

import (
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestAppendIfMissingUniqueness(t *testing.T) {
	t.Parallel()

	// DNA TAGC Append M
	after := strings.Split("CTTCGGTTGTCAAGGAACTGTTG", "")
	after = appendIfMissing(after, strings.Split("MCTGAACGTGCATGCATGCATGGTCATGCATGTTTGTGCATAAAATGTGAGATGAGAAA", "")...)

	// DNA TAGC + M (in order as it appears)
	want := strings.Split("CTGAM", "")

	assert.Equal(t, want, after)

	// Append some alphabet things
	after = appendIfMissing(after, "A", "B", "C", "D", "E", "F", "E", "F", "E", "F")
	want = append(want, "B", "D", "E", "F")

	assert.Equal(t, want, after)
}

func Test_shouldReloadSpec(t *testing.T) {
	t.Parallel()
	t.Run("empty curr spec", func(t *testing.T) {
		t.Parallel()
		assert.True(t, shouldReloadSpec(nil, &APISpec{}))
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		t.Parallel()
		existingSpec, newSpec := &APISpec{Checksum: "1"}, &APISpec{Checksum: "2"}
		assert.True(t, shouldReloadSpec(existingSpec, newSpec))
	})

	type testCase struct {
		name string
		spec *APISpec
		want bool
	}

	assertionHelper := func(t *testing.T, tcs []testCase) {
		t.Helper()
		for i := 0; i < len(tcs); i++ {
			tc := tcs[i]
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := shouldReloadSpec(&APISpec{}, tc.spec); got != tc.want {
					t.Errorf("shouldReloadSpec() = %v, want %v", got, tc.want)
				}
			})
		}
	}

	t.Run("virtual endpoint", func(t *testing.T) {
		t.Parallel()
		virtualEndpointAPIDef := &apidef.APIDefinition{}
		virtualEndpointAPIDef.VersionData.Versions = map[string]apidef.VersionInfo{
			"": {
				ExtendedPaths: apidef.ExtendedPathsSet{
					Virtual: []apidef.VirtualMeta{
						{
							ResponseFunctionName: "respFuncName",
						},
					},
				},
			},
		}
		tcs := []testCase{
			{
				name: "with virutal endpoint",
				spec: &APISpec{APIDefinition: virtualEndpointAPIDef},
				want: true,
			},
			{
				name: "without virutal endpoint",
				spec: &APISpec{APIDefinition: &apidef.APIDefinition{}},
				want: false,
			},
		}

		assertionHelper(t, tcs)
	})

	t.Run("driver", func(t *testing.T) {
		t.Parallel()
		tcs := []testCase{
			{
				name: "grpc",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							Driver: apidef.GrpcDriver,
							Pre: []apidef.MiddlewareDefinition{
								{
									Name: "funcName",
								},
							},
						},
					},
				},
				want: false,
			},
			{
				name: "goplugin",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							Driver: apidef.GoPluginDriver,
							Pre: []apidef.MiddlewareDefinition{
								{
									Name: "funcName",
								},
							},
						},
					},
				},
				want: true,
			},
		}

		assertionHelper(t, tcs)
	})

	t.Run("mw enabled", func(t *testing.T) {
		t.Parallel()
		tcs := []testCase{
			{
				name: "auth",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							AuthCheck: apidef.MiddlewareDefinition{
								Name: "auth",
								Path: "path",
							},
						},
					},
				},
				want: true,
			},
			{
				name: "pre",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							Pre: []apidef.MiddlewareDefinition{
								{
									Name: "pre",
									Path: "path",
								},
							},
						},
					},
				},
				want: true,
			},
			{
				name: "postKeyAuth",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							PostKeyAuth: []apidef.MiddlewareDefinition{
								{
									Name: "postAuth",
									Path: "path",
								},
							},
						},
					},
				},
				want: true,
			},
			{
				name: "post",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							Post: []apidef.MiddlewareDefinition{
								{
									Name: "post",
									Path: "path",
								},
							},
						},
					},
				},
				want: true,
			},
			{
				name: "response",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddleware: apidef.MiddlewareSection{
							Response: []apidef.MiddlewareDefinition{
								{
									Name: "response",
									Path: "path",
								},
							},
						},
					},
				},
				want: true,
			},
		}

		assertionHelper(t, tcs)
	})
}

func TestAreMapsEqual(t *testing.T) {
	tests := []struct {
		name     string
		map1     map[string]string
		map2     map[string]string
		expected bool
	}{
		{
			name:     "Equal maps",
			map1:     map[string]string{"key1": "value1", "key2": "value2"},
			map2:     map[string]string{"key1": "value1", "key2": "value2"},
			expected: true,
		},
		{
			name:     "Different maps",
			map1:     map[string]string{"key1": "value1", "key2": "value2"},
			map2:     map[string]string{"key1": "value1", "key2": "value3"},
			expected: false,
		},
		{
			name:     "Different sizes",
			map1:     map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			map2:     map[string]string{"key1": "value1", "key2": "value2"},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := areMapsEqual(test.map1, test.map2)
			if result != test.expected {
				t.Errorf("areMapsEqual() = %v, want %v", result, test.expected)
			}
		})
	}
}

func TestContainsEscapedCharacters(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{
			value:    "payment%2Dintents",
			expected: true,
		},
		{
			value:    "payment-intents",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			result := containsEscapedChars(test.value)
			if result != test.expected {
				t.Errorf("containsEscapedChars() = %v, want %v", result, test.expected)
			}
		})
	}
}
