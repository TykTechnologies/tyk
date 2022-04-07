package oas

import (
	"fmt"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func getStrPointer(str string) *string {
	return &str
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
	validOAS3Definition, _ := validOASObject.MarshalJSON()

	t.Run("valid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS3Definition, "3.0.3")
		assert.Nil(t, err)
	})

	invalidOASObject := validOASObject
	invalidOASObject.Paths["/pets"].Get.Responses["200"].Value.Description = nil
	invalidOAS3Definition, _ := invalidOASObject.MarshalJSON()

	t.Run("invalid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(invalidOAS3Definition, "3.0.3")
		expectedErr := fmt.Sprintf("%s\n%s",
			"paths./pets.get.responses.200: Must validate one and only one schema (oneOf)",
			"paths./pets.get.responses.200: description is required",
		)
		assert.Equal(t, expectedErr, err.Error())
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
}

func Test_loadOASSchema(t *testing.T) {
	t.Parallel()
	t.Run("load OAS", func(t *testing.T) {
		t.Parallel()
		err := loadOASSchema()
		assert.Nil(t, err)
		assert.NotNil(t, oasJsonSchemas["3.0.3"])
	})
}

func Test_findDefaultVersion(t *testing.T) {
	t.Parallel()
	t.Run("single version", func(t *testing.T) {
		rawVersions := []string{"3.0.3"}

		assert.Equal(t, "3.0.3", findDefaultVersion(rawVersions))
	})

	t.Run("multiple versions", func(t *testing.T) {
		rawVersions := []string{"3.0.3", "3.0.4", "3.1.0"}

		assert.Equal(t, "3.1.0", findDefaultVersion(rawVersions))
	})
}

func Test_setDefaultVersion(t *testing.T) {
	err := loadOASSchema()
	assert.NoError(t, err)

	setDefaultVersion()
	assert.Equal(t, "3.0.3", defaultVersion)
}
