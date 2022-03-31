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
			Info: &openapi3.Info{
				Version: "1.0.0",
				Title:   "Swagger Petstore",
				License: &openapi3.License{
					Name: "MIT",
				},
			},
			Servers: []*openapi3.Server{
				{
					URL: "http://petstore.swagger.io/v1",
				},
			},
			Paths: map[string]*openapi3.PathItem{
				"/pets": {
					Get: &openapi3.Operation{
						Summary:     "List all pets",
						OperationID: "listPets",
						Tags: []string{
							"pets",
						},
						Parameters: []*openapi3.ParameterRef{
							{
								Value: &openapi3.Parameter{
									Name:        "limit",
									In:          "query",
									Description: "How many items to return at one time (max 100)",
									Required:    false,
									Schema: &openapi3.SchemaRef{
										Value: &openapi3.Schema{
											Type:   "integer",
											Format: "int32",
										},
									},
								},
							},
						},
						Responses: openapi3.Responses{
							"200": &openapi3.ResponseRef{
								Value: &openapi3.Response{
									Description: getStrPointer("A paged array of pets"),
									Content: openapi3.Content{
										"application/json": {
											Schema: &openapi3.SchemaRef{
												Ref: "#/components/schemas/Pets",
											},
										},
									},
								},
							},
							"default": &openapi3.ResponseRef{
								Value: &openapi3.Response{
									Description: getStrPointer("unexpected error"),
									Content: openapi3.Content{
										"application/json": {
											Schema: &openapi3.SchemaRef{
												Ref: "#/components/schemas/Error",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Components: openapi3.Components{
				Schemas: map[string]*openapi3.SchemaRef{
					"Pet": {
						Value: &openapi3.Schema{
							Type: "object",
							Required: []string{
								"id",
								"name",
							},
							Properties: map[string]*openapi3.SchemaRef{
								"id": {
									Value: &openapi3.Schema{
										Type:   "integer",
										Format: "int64",
									},
								},
								"name": {
									Value: &openapi3.Schema{
										Type: "string",
									},
								},
								"tag": {
									Value: &openapi3.Schema{
										Type: "string",
									},
								},
							},
						},
					},
					"Pets": {
						Value: &openapi3.Schema{
							Type: "array",
							Items: &openapi3.SchemaRef{
								Ref: "#/components/schemas/Pet",
							},
						},
					},
					"Error": {
						Value: &openapi3.Schema{
							Type: "object",
							Required: []string{
								"code",
								"message",
							},
							Properties: map[string]*openapi3.SchemaRef{
								"code": {
									Value: &openapi3.Schema{
										Type:   "integer",
										Format: "int32",
									},
								},
								"message": {
									Value: &openapi3.Schema{
										Type: "string",
									},
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
