package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func getStrPointer(str string) *string {
	return &str
}

func TestValidateMCPObject(t *testing.T) {
	t.Parallel()

	validOASObject := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{},
			Paths:   openapi3.NewPaths(),
		},
	}

	validXTykAPIGateway := oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "mcp-api",
			State: oas.State{
				Active: true,
			},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/mcp-api",
			},
		},
		Upstream: oas.Upstream{
			URL: "http://upstream.url",
		},
		Middleware: &oas.Middleware{
			McpTools: map[string]*oas.MCPPrimitive{
				"test-tool": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
			},
		},
	}

	validOASObject.SetTykExtension(&validXTykAPIGateway)
	validMCP3Definition, err := validOASObject.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal valid OAS object: %v", err)
	}

	t.Run("valid MCP object", func(t *testing.T) {
		t.Parallel()
		err := ValidateMCPObject(validMCP3Definition, "3.0.3")
		assert.Nil(t, err)
	})

	t.Run("valid MCP object with resources", func(t *testing.T) {
		t.Parallel()
		mcpWithResources := validOASObject
		extWithResources := validXTykAPIGateway
		extWithResources.Middleware = &oas.Middleware{
			McpResources: map[string]*oas.MCPPrimitive{
				"test-resource": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
			},
		}
		mcpWithResources.SetTykExtension(&extWithResources)
		definition, err := mcpWithResources.MarshalJSON()
		if err != nil {
			t.Fatalf("failed to marshal MCP with resources: %v", err)
		}

		err = ValidateMCPObject(definition, "3.0.3")
		assert.Nil(t, err)
	})

	t.Run("valid MCP object with prompts", func(t *testing.T) {
		t.Parallel()
		mcpWithPrompts := validOASObject
		extWithPrompts := validXTykAPIGateway
		extWithPrompts.Middleware = &oas.Middleware{
			McpPrompts: map[string]*oas.MCPPrimitive{
				"test-prompt": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{
							Enabled: true,
						},
					},
				},
			},
		}
		mcpWithPrompts.SetTykExtension(&extWithPrompts)
		definition, err := mcpWithPrompts.MarshalJSON()
		if err != nil {
			t.Fatalf("failed to marshal MCP with prompts: %v", err)
		}

		err = ValidateMCPObject(definition, "3.0.3")
		assert.Nil(t, err)
	})

	t.Run("valid MCP object with all MCP fields", func(t *testing.T) {
		t.Parallel()
		mcpWithAll := validOASObject
		extWithAll := validXTykAPIGateway
		extWithAll.Middleware = &oas.Middleware{
			McpTools: map[string]*oas.MCPPrimitive{
				"tool1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: true},
					},
				},
			},
			McpResources: map[string]*oas.MCPPrimitive{
				"resource1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: true},
					},
				},
			},
			McpPrompts: map[string]*oas.MCPPrimitive{
				"prompt1": {
					Operation: oas.Operation{
						Allow: &oas.Allowance{Enabled: true},
					},
				},
			},
		}
		mcpWithAll.SetTykExtension(&extWithAll)
		definition, err := mcpWithAll.MarshalJSON()
		if err != nil {
			t.Fatalf("failed to marshal MCP with all fields: %v", err)
		}

		err = ValidateMCPObject(definition, "3.0.3")
		assert.Nil(t, err)
	})

	invalidOASObject := validOASObject
	invalidXTykAPIGateway := validXTykAPIGateway
	invalidXTykAPIGateway.Info = oas.Info{} // Empty name should fail
	invalidXTykAPIGateway.Server.GatewayTags = &oas.GatewayTags{Enabled: true, Tags: []string{}}
	invalidOASObject.SetTykExtension(&invalidXTykAPIGateway)
	invalidMCP3Definition, err := invalidOASObject.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal invalid OAS object: %v", err)
	}

	t.Run("invalid MCP object", func(t *testing.T) {
		t.Parallel()
		err := ValidateMCPObject(invalidMCP3Definition, "3.0.3")
		expectedErrs := []string{
			`x-tyk-api-gateway.info.name: Does not match pattern '\S+'`,
		}
		actualErrs := strings.Split(err.Error(), "\n")
		assert.ElementsMatch(t, expectedErrs, actualErrs)
	})

	var wrongTypedMCPDefinition = []byte(`{
		"openapi": "3.0.0",
		"info": {
			"version": "1.0.0",
			"title": "MCP Test API",
			"license": {
				"name": "MIT"
			}
		},
		"servers": [
			{
				"url": "http://mcp.example.io/v1"
			}
		],
		"paths": {
			"/test": {
				"get": {
					"summary": "Test endpoint",
					"operationId": "testOp",
					"tags": "test"
				}
			}
		},
		"x-tyk-api-gateway": {
			"info": {
				"name": "mcp-test",
				"state": {
					"active": true
				}
			},
			"upstream": {
				"url": "http://upstream.url"
			},
			"server": {
				"listenPath": {
					"value": "/mcp-test"
				}
			}
		}
	}`)

	t.Run("wrong typed MCP object", func(t *testing.T) {
		t.Parallel()
		err := ValidateMCPObject(wrongTypedMCPDefinition, "3.0.3")
		expectedErr := fmt.Sprintf("%s\n%s",
			"paths./test.get: responses is required",
			"paths./test.get.tags: Invalid type. Expected: array, given: string")
		assert.Equal(t, expectedErr, err.Error())
	})

	t.Run("should error when requested mcp schema not found", func(t *testing.T) {
		t.Parallel()
		reqOASVersion := "4.0.3"
		err := ValidateMCPObject(validMCP3Definition, reqOASVersion)
		expectedErr := fmt.Errorf(mcpSchemaVersionNotFoundFmt, reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})
}

func TestValidateMCPObject_3_1(t *testing.T) {
	t.Parallel()

	// Create minimal valid MCP 3.1 document
	validMCP31Doc := []byte(`{
		"openapi": "3.1.0",
		"info": {
			"title": "MCP API 3.1",
			"version": "1.0.0"
		},
		"paths": {
			"/test": {
				"get": {
					"responses": {
						"200": {
							"description": "Success"
						}
					}
				}
			}
		},
		"x-tyk-api-gateway": {
			"info": {
				"name": "mcp-api-3.1",
				"state": {
					"active": true
				}
			},
			"upstream": {
				"url": "http://localhost:8080"
			},
			"server": {
				"listenPath": {
					"value": "/mcp-api-3.1/"
				}
			},
			"middleware": {
				"mcpTools": {
					"test-tool": {
						"allow": {
							"enabled": true
						}
					}
				}
			}
		}
	}`)

	t.Run("valid MCP 3.1 document with version 3.1.0", func(t *testing.T) {
		t.Parallel()
		err := ValidateMCPObject(validMCP31Doc, "3.1.0")
		assert.NoError(t, err)
	})

	t.Run("valid MCP 3.1 document with version 3.1", func(t *testing.T) {
		t.Parallel()
		err := ValidateMCPObject(validMCP31Doc, "3.1")
		assert.NoError(t, err)
	})
}

func Test_loadMCPSchema(t *testing.T) {
	t.Parallel()
	t.Run("load MCP schemas", func(t *testing.T) {
		t.Parallel()
		err := loadMCPSchema()
		assert.Nil(t, err)
		assert.NotNil(t, mcpJSONSchemas)

		// Verify we have at least 3.0 and 3.1 schemas
		assert.Contains(t, mcpJSONSchemas, "3.0", "Should load MCP 3.0 schema")
		assert.Contains(t, mcpJSONSchemas, "3.1", "Should load MCP 3.1 schema")

		for mcpVersion, schemaData := range mcpJSONSchemas {
			// Check x-tyk-api-gateway extension is in properties
			var xTykAPIGateway []byte
			xTykAPIGateway, _, _, err = jsonparser.Get(schemaData, keyProperties, ExtensionTykAPIGateway)
			assert.NoError(t, err, "x-tyk-api-gateway should exist in properties for version %s", mcpVersion)
			assert.NotNil(t, xTykAPIGateway, "x-tyk-api-gateway should not be nil for version %s", mcpVersion)

			// Detect which definitions key this version uses
			defsKey := GetDefinitionsKey(schemaData)

			// Check X-Tyk-Server is in the correct definitions location
			var xTykServer []byte
			xTykServer, _, _, err = jsonparser.Get(schemaData, defsKey, "X-Tyk-Server")
			assert.NoError(t, err, "X-Tyk-Server should exist in %s for version %s", defsKey, mcpVersion)
			assert.NotNil(t, xTykServer, "X-Tyk-Server should not be nil for version %s", mcpVersion)

			// Verify the correct key is used based on version
			if strings.HasPrefix(mcpVersion, "3.0") {
				assert.Equal(t, "definitions", defsKey, "MCP 3.0 should use 'definitions'")
			} else if strings.HasPrefix(mcpVersion, "3.1") {
				assert.Equal(t, "$defs", defsKey, "MCP 3.1 should use '$defs'")
			}
		}
	})
}

func TestGetDefinitionsKey(t *testing.T) {
	t.Parallel()

	t.Run("returns $defs for MCP 3.1 schema", func(t *testing.T) {
		t.Parallel()
		schema31 := []byte(`{"$defs": {}, "properties": {}}`)
		key := GetDefinitionsKey(schema31)
		assert.Equal(t, "$defs", key)
	})

	t.Run("returns definitions for MCP 3.0 schema", func(t *testing.T) {
		t.Parallel()
		schema30 := []byte(`{"definitions": {}, "properties": {}}`)
		key := GetDefinitionsKey(schema30)
		assert.Equal(t, "definitions", key)
	})

	t.Run("falls back to definitions when neither key exists", func(t *testing.T) {
		t.Parallel()
		schemaUnknown := []byte(`{"properties": {}}`)
		key := GetDefinitionsKey(schemaUnknown)
		assert.Equal(t, "definitions", key)
	})

	t.Run("prefers $defs when both keys exist", func(t *testing.T) {
		t.Parallel()
		schemaBoth := []byte(`{"$defs": {}, "definitions": {}, "properties": {}}`)
		key := GetDefinitionsKey(schemaBoth)
		assert.Equal(t, "$defs", key)
	})
}

func Test_findDefaultVersion(t *testing.T) {
	t.Parallel()
	t.Run("single version", func(t *testing.T) {
		rawVersions := []string{"3.0"}

		assert.Equal(t, "3.0", findDefaultVersion(rawVersions))
	})

	t.Run("multiple versions", func(t *testing.T) {
		rawVersions := []string{"3.0", "2.0", "3.1.0"}

		assert.Equal(t, "3.1", findDefaultVersion(rawVersions))
	})
}

func Test_setDefaultVersion(t *testing.T) {
	err := loadMCPSchema()
	assert.NoError(t, err)

	setDefaultVersion()
	assert.Equal(t, "3.0", defaultVersion)
}

func TestGetMCPSchema(t *testing.T) {
	err := loadMCPSchema()
	assert.NoError(t, err)

	t.Run("return default version when req version is empty", func(t *testing.T) {
		schema, err := GetMCPSchema("")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)
		assert.NotEmpty(t, mcpJSONSchemas["3.0"])
	})

	t.Run("return minor version schema when req version is including patch version", func(t *testing.T) {
		schema, err := GetMCPSchema("3.0.8")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)
		assert.NotEmpty(t, mcpJSONSchemas["3.0"])
	})

	t.Run("return minor version 0 when only major version is requested", func(t *testing.T) {
		schema, err := GetMCPSchema("3")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)
		assert.NotEmpty(t, mcpJSONSchemas["3.0"])
	})

	t.Run("return error when non existing mcp schema is requested", func(t *testing.T) {
		reqOASVersion := "4.0.3"
		_, err = GetMCPSchema(reqOASVersion)
		expectedErr := fmt.Errorf(mcpSchemaVersionNotFoundFmt, reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("return error when requested version is not of semver", func(t *testing.T) {
		reqOASVersion := "a.0.3"
		_, err = GetMCPSchema(reqOASVersion)
		expectedErr := fmt.Errorf("Malformed version: %s", reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("return 3.1 schema when version 3.1 is requested", func(t *testing.T) {
		schema, err := GetMCPSchema("3.1")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)

		// Verify it's the 3.1 schema by checking it uses $defs
		defsKey := GetDefinitionsKey(schema)
		assert.Equal(t, "$defs", defsKey, "MCP 3.1 schema should use $defs")
	})

	t.Run("return 3.1 schema when version 3.1.0 is requested", func(t *testing.T) {
		schema, err := GetMCPSchema("3.1.0")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)

		// Verify it's the 3.1 schema
		defsKey := GetDefinitionsKey(schema)
		assert.Equal(t, "$defs", defsKey)
	})
}

func TestValidateMCPObject_WithPRM(t *testing.T) {
	t.Parallel()

	t.Run("valid MCP object with PRM configuration", func(t *testing.T) {
		t.Parallel()

		mcpWithPRM := oas.OAS{
			T: openapi3.T{
				OpenAPI: "3.0.3",
				Info:    &openapi3.Info{},
				Paths:   openapi3.NewPaths(),
			},
		}

		ext := oas.XTykAPIGateway{
			Info: oas.Info{
				Name: "mcp-api-prm",
				State: oas.State{
					Active: true,
				},
			},
			Server: oas.Server{
				ListenPath: oas.ListenPath{
					Value: "/mcp-api-prm/",
				},
				Authentication: &oas.Authentication{
					Enabled: true,
					ProtectedResourceMetadata: &oas.ProtectedResourceMetadata{
						Enabled:              true,
						Resource:             "https://api.example.com",
						AuthorizationServers: []string{"https://auth.example.com"},
						ScopesSupported:      []string{"read", "write"},
					},
				},
			},
			Upstream: oas.Upstream{
				URL: "http://upstream.url",
			},
			Middleware: &oas.Middleware{
				McpTools: map[string]*oas.MCPPrimitive{
					"test-tool": {
						Operation: oas.Operation{
							Allow: &oas.Allowance{
								Enabled: true,
							},
						},
					},
				},
			},
		}

		mcpWithPRM.SetTykExtension(&ext)
		definition, err := mcpWithPRM.MarshalJSON()
		if err != nil {
			t.Fatalf("failed to marshal MCP with PRM: %v", err)
		}

		err = ValidateMCPObject(definition, "3.0.3")
		assert.NoError(t, err)
	})
}

func TestValidateMCPObject_RestrictedMiddleware(t *testing.T) {
	t.Parallel()

	buildMCPDoc := func(toolMiddleware string) []byte {
		return []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "MCP Test", "version": "1.0.0"},
			"paths": {
				"/test": {
					"post": {
						"responses": {"200": {"description": "OK"}}
					}
				}
			},
			"x-tyk-api-gateway": {
				"info": {
					"name": "mcp-test",
					"state": {"active": true}
				},
				"upstream": {"url": "http://upstream.url"},
				"server": {
					"listenPath": {"value": "/mcp-test"}
				},
				"middleware": {
					"mcpTools": {
						"test-tool": ` + toolMiddleware + `
					}
				}
			}
		}`)
	}

	t.Run("allowed fields pass validation", func(t *testing.T) {
		t.Parallel()
		doc := buildMCPDoc(`{
			"allow": {"enabled": true},
			"rateLimit": {"enabled": true, "rate": 100, "per": "1m"},
			"requestSizeLimit": {"enabled": true, "value": 1024}
		}`)
		err := ValidateMCPObject(doc, "3.0.3")
		assert.NoError(t, err)
	})

	// Restricted middleware fields are accepted by schema (permissive validation for forward compatibility).
	// Enforcement happens at extraction layer (see TestMCPPrimitive_DisabledMiddleware).
	restrictedFields := []struct {
		name       string
		middleware string
	}{
		{
			name:       "urlRewrite accepted by schema (ignored at extraction)",
			middleware: `{"urlRewrite": {"enabled": true, "pattern": ".*", "rewriteTo": "/new"}}`,
		},
		{
			name:       "transformRequestMethod accepted by schema (ignored at extraction)",
			middleware: `{"transformRequestMethod": {"enabled": true, "toMethod": "GET"}}`,
		},
		{
			name:       "transformResponseBody accepted by schema (ignored at extraction)",
			middleware: `{"transformResponseBody": {"enabled": true, "format": "json", "body": "test"}}`,
		},
		{
			name:       "internal accepted by schema (ignored at extraction)",
			middleware: `{"internal": {"enabled": true}}`,
		},
		{
			name:       "cache accepted by schema (ignored at extraction)",
			middleware: `{"cache": {"enabled": true}}`,
		},
		{
			name:       "validateRequest accepted by schema (ignored at extraction)",
			middleware: `{"validateRequest": {"enabled": true}}`,
		},
		{
			name:       "mockResponse accepted by schema (ignored at extraction)",
			middleware: `{"mockResponse": {"enabled": true}}`,
		},
	}

	for _, tc := range restrictedFields {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := buildMCPDoc(tc.middleware)
			err := ValidateMCPObject(doc, "3.0.3")
			assert.NoError(t, err, "Schema should accept %s for forward compatibility", tc.name)
		})
	}
}

func TestGetMCPSchema_ContainsMCPExtensions(t *testing.T) {
	t.Parallel()

	err := loadMCPSchema()
	assert.NoError(t, err)

	t.Run("MCP schema contains x-tyk-api-gateway extension", func(t *testing.T) {
		t.Parallel()
		schema, err := GetMCPSchema("3.0")
		assert.NoError(t, err)

		// Verify x-tyk-api-gateway property exists
		_, _, _, err = jsonparser.Get(schema, keyProperties, ExtensionTykAPIGateway)
		assert.NoError(t, err, "x-tyk-api-gateway should be present in MCP schema")
	})
}
