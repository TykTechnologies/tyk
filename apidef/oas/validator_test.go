package oas

import (
	"fmt"
	"strings"
	"testing"

	"github.com/buger/jsonparser"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func getStrPointer(str string) *string {
	return &str
}

func getBoolPointer(b bool) *bool {
	return &b
}

func TestValidateOASObject(t *testing.T) {
	t.Parallel()
	validOASObject := OAS{
		openapi3.T{
			OpenAPI: "3.0.3",
			Info:    &openapi3.Info{},
			Paths: map[string]*openapi3.PathItem{
				"/pets": {
					Get: &openapi3.Operation{
						Responses: openapi3.Responses{
							"200": &openapi3.ResponseRef{
								Value: &openapi3.Response{
									Description: getStrPointer("A paged array of pets"),
								},
							},
						},
					},
				},
			},
		},
	}

	validXTykAPIGateway := XTykAPIGateway{
		Info: Info{
			Name: "oas-api",
			State: State{
				Active: true,
			},
		},
		Server: Server{
			ListenPath: ListenPath{
				Value: "/oas-api",
			},
		},
		Upstream: Upstream{
			URL: "http://upstream.url",
		},
	}

	validOASObject.SetTykExtension(&validXTykAPIGateway)

	validOAS3Definition, _ := validOASObject.MarshalJSON()

	t.Run("valid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS3Definition, "3.0.3")
		assert.Nil(t, err)
	})

	invalidOASObject := validOASObject
	invalidXTykAPIGateway := validXTykAPIGateway
	invalidXTykAPIGateway.Info = Info{}
	invalidXTykAPIGateway.Server.GatewayTags = &GatewayTags{Enabled: true, Tags: []string{}}
	invalidOASObject.SetTykExtension(&invalidXTykAPIGateway)
	invalidOASObject.Paths["/pets"].Get.Responses["200"].Value.Description = nil
	invalidOAS3Definition, _ := invalidOASObject.MarshalJSON()

	t.Run("invalid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(invalidOAS3Definition, "3.0.3")
		expectedErrs := []string{
			`x-tyk-api-gateway.info.name: Does not match pattern '\S+'`,
			"paths./pets.get.responses.200: Must validate one and only one schema (oneOf)",
			"paths./pets.get.responses.200: description is required",
		}
		actualErrs := strings.Split(err.Error(), "\n")
		assert.ElementsMatch(t, expectedErrs, actualErrs)
	})

	var wrongTypedOASDefinition = []byte(`{
	"openapi": "3.0.0",
	"info": {
	"version": "1.0.0",
	"title": "Swagger Petstore",
	"license": {
	  "name": "MIT"
	}
	},
	"servers": [
	{
	  "url": "http://petstore.swagger.io/v1"
	}
	],
	"paths": {
	"/pets": {
	  "get": {
		"summary": "List all pets",
		"operationId": "listPets",
		"tags": "pets",
		"parameters": [
		  {
			"name": "limit",
			"in": "query",
			"description": "How many items to return at one time (max 100)",
			"required": false,
			"schema": {
			  "type": "integer",
			  "format": "int32"
			}
		  }
		]
	  }
	}
	},
	"components": {
	"schemas": {
	  "Pet": {
		"type": "object",
		"required": [
		  "id",
		  "name"
		],
		"properties": {
		  "id": {
			"type": "integer",
			"format": "int64"
		  },
		  "name": {
			"type": "string"
		  },
		  "tag": {
			"type": "string"
		  }
		}
	  },
	  "Pets": {
		"type": "array",
		"items": {
		  "$ref": "#/components/schemas/Pet"
		}
	  },
	  "Error": {
		"type": "object",
		"required": [
		  "code",
		  "message"
		],
		"properties": {
		  "code": {
			"type": "integer",
			"format": "int32"
		  },
		  "message": {
			"type": "string"
		  }
		}
	  }
	}
	}
	}`)

	t.Run("wrong typed OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(wrongTypedOASDefinition, "3.0.3")
		expectedErr := fmt.Sprintf("%s\n%s",
			"paths./pets.get: responses is required",
			"paths./pets.get.tags: Invalid type. Expected: array, given: string")
		assert.Equal(t, expectedErr, err.Error())
	})

	t.Run("should error when requested oas schema not found", func(t *testing.T) {
		t.Parallel()
		reqOASVersion := "4.0.3"
		err := ValidateOASObject(validOAS3Definition, reqOASVersion)
		expectedErr := fmt.Errorf(oasSchemaVersionNotFoundFmt, reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})
}

func Test_loadOASSchema(t *testing.T) {
	t.Parallel()
	t.Run("load OAS", func(t *testing.T) {
		t.Parallel()
		err := loadOASSchema()
		assert.Nil(t, err)
		assert.NotNil(t, oasJSONSchemas)
		for oasVersion := range oasJSONSchemas {
			var xTykAPIGateway, xTykServer []byte
			xTykAPIGateway, _, _, err = jsonparser.Get(oasJSONSchemas[oasVersion], keyProperties, ExtensionTykAPIGateway)
			assert.NoError(t, err)
			assert.NotNil(t, xTykAPIGateway)

			xTykServer, _, _, err = jsonparser.Get(oasJSONSchemas[oasVersion], keyDefinitions, "X-Tyk-Server")
			assert.NoError(t, err)
			assert.NotNil(t, xTykServer)
		}
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
	err := loadOASSchema()
	assert.NoError(t, err)

	setDefaultVersion()
	assert.Equal(t, "3.0", defaultVersion)
}

func TestGetOASSchema(t *testing.T) {
	err := loadOASSchema()
	assert.NoError(t, err)

	t.Run("return default version when req version is empty", func(t *testing.T) {
		_, err = GetOASSchema("")
		assert.NoError(t, err)
		assert.NotEmpty(t, oasJSONSchemas["3.0"])
	})

	t.Run("return minor version schema when req version is including patch version", func(t *testing.T) {
		_, err = GetOASSchema("3.0.8")
		assert.NoError(t, err)
		assert.NotEmpty(t, oasJSONSchemas["3.0"])
	})

	t.Run("return minor version 0 when only major version is requested", func(t *testing.T) {
		_, err = GetOASSchema("3")
		assert.NoError(t, err)
		assert.NotEmpty(t, oasJSONSchemas["3.0"])
	})

	t.Run("return error when non existing oas schema is requested", func(t *testing.T) {
		reqOASVersion := "4.0.3"
		_, err = GetOASSchema(reqOASVersion)
		expectedErr := fmt.Errorf(oasSchemaVersionNotFoundFmt, reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("return error when requested version is not of semver", func(t *testing.T) {
		reqOASVersion := "a.0.3"
		_, err = GetOASSchema(reqOASVersion)
		expectedErr := fmt.Errorf("Malformed version: %s", reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})
}
