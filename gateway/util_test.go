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
