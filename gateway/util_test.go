package gateway

import (
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"

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

func Test_getAPIURL(t *testing.T) {
	t.Parallel()
	type args struct {
		apiDef   apidef.APIDefinition
		gwConfig config.Config
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "https enabled with api domain",
			args: args{
				apiDef: apidef.APIDefinition{
					Domain: "example.com",
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					HttpServerOptions: config.HttpServerOptionsConfig{
						UseSSL: true,
					},
				},
			},
			want: "https://example.com/api",
		},

		{
			name: "https disabled with api domain",
			args: args{
				apiDef: apidef.APIDefinition{
					Domain: "example.com",
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{},
			},
			want: "http://example.com/api",
		},

		{
			name: "https disabled without api domain",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "127.0.0.1",
					ListenPort:    8080,
				},
			},
			want: "http://127.0.0.1:8080/api",
		},

		{
			name: "https enabled and configured listen address and port 443",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "10.0.0.1",
					ListenPort:    443,
					HttpServerOptions: config.HttpServerOptionsConfig{
						UseSSL: true,
					},
				},
			},
			want: "https://10.0.0.1/api",
		},

		{
			name: "without api domain and configured listen address",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "10.0.0.1",
					ListenPort:    8080,
					HttpServerOptions: config.HttpServerOptionsConfig{
						UseSSL: true,
					},
				},
			},
			want: "https://10.0.0.1:8080/api",
		},

		{
			name: "configured listen address with 80 port",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "10.0.0.1",
					ListenPort:    80,
				},
			},
			want: "http://10.0.0.1/api",
		},

		{
			name: "without api domain and no configured listen address",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenPort: 8080,
					HttpServerOptions: config.HttpServerOptionsConfig{
						UseSSL: true,
					},
				},
			},
			want: "https://127.0.0.1:8080/api",
		},

		{
			name: "no configured listen address with 80 port",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenPort: 80,
				},
			},
			want: "http://127.0.0.1/api",
		},

		{
			name: "gw hostname non 80 port",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "127.0.0.1",
					ListenPort:    8080,
					HostName:      "example-host.org",
				},
			},
			want: "http://example-host.org:8080/api",
		},

		{
			name: "gw hostname with port 80",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "127.0.0.1",
					ListenPort:    80,
					HostName:      "example-host.org",
				},
			},
			want: "http://example-host.org/api",
		},

		{
			name: "https enabled gw hostname with port 443",
			args: args{
				apiDef: apidef.APIDefinition{
					Proxy: apidef.ProxyConfig{
						ListenPath: "/api",
					},
				},
				gwConfig: config.Config{
					ListenAddress: "127.0.0.1",
					ListenPort:    443,
					HostName:      "example-host.org",
					HttpServerOptions: config.HttpServerOptionsConfig{
						UseSSL: true,
					},
				},
			},

			want: "https://example-host.org/api",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, getAPIURL(tt.args.apiDef, tt.args.gwConfig), "getAPIURL(%v, %v)", tt.args.apiDef, tt.args.gwConfig)
		})
	}
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
		tcs := []testCase{
			{
				name: "disabled",
				spec: &APISpec{APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									Virtual: []apidef.VirtualMeta{
										{
											Disabled: false,
										},
									},
								},
							},
						},
					},
				},
				},
				want: true,
			},
			{
				name: "enabled",
				spec: &APISpec{APIDefinition: &apidef.APIDefinition{
					VersionData: apidef.VersionData{
						Versions: map[string]apidef.VersionInfo{
							"": {
								ExtendedPaths: apidef.ExtendedPathsSet{
									Virtual: []apidef.VirtualMeta{
										{
											Disabled: true,
										},
									},
								},
							},
						},
					},
				},
				},
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
									Disabled: false,
									Name:     "funcName",
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
									Disabled: false,
									Name:     "funcName",
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
								Disabled: false,
								Name:     "auth",
								Path:     "path",
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
									Disabled: false,
									Name:     "pre",
									Path:     "path",
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
									Disabled: false,
									Name:     "postAuth",
									Path:     "path",
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
									Disabled: false,
									Name:     "post",
									Path:     "path",
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
									Disabled: false,
									Name:     "response",
									Path:     "path",
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

	t.Run("bundle", func(t *testing.T) {
		t.Parallel()
		tcs := []testCase{
			{
				name: "bundle disabled",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundleDisabled: true,
						CustomMiddlewareBundle:         "bundle.zip",
					},
				},
				want: false,
			},
			{
				name: "bundle enabled with empty bundle value",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundleDisabled: false,
						CustomMiddlewareBundle:         "",
					},
				},
				want: false,
			},
			{
				name: "bundle enabled with valid bundle value",
				spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundleDisabled: false,
						CustomMiddlewareBundle:         "bundle.zip",
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
