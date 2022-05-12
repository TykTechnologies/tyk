package oas

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOAS_BuildDefaultTykExtension(t *testing.T) {
	t.Parallel()

	t.Run("build tyk extension with no supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.NoError(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/",
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("build tyk extension with supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/listen-api",
			UpstreamURL: "https://example.org/api",
		})

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("do not override existing tyk extension by default", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("override existing tyk extension with supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/new-listen-api",
			UpstreamURL: "https://example.org/api",
		})

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-api",
				},
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("error when supplied invalid upstreamURL param", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/new-listen-api",
			UpstreamURL: "invalid-url",
		})
		assert.ErrorIs(t, err, errInvalidUpstreamURL)
	})

	t.Run("error when no supplied params and invalid URL in servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "/listen-api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		expectedErrStr := fmt.Sprintf(invalidServerURLFmt, oasDef.Servers[0].URL)
		assert.EqualError(t, err, expectedErrStr)
	})

	t.Run("error when no supplied params and no servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.ErrorIs(t, err, errEmptyServersObject)
	})
}
