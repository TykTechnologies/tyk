package oas

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/stretchr/testify/assert"
)

func TestOAS(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var emptyOAS OAS

		var convertedAPI apidef.APIDefinition
		emptyOAS.ExtractTo(&convertedAPI)

		var resultOAS OAS
		resultOAS.Fill(convertedAPI)

		assert.Equal(t, emptyOAS, resultOAS)
	})

	var api apidef.APIDefinition
	api.AuthConfigs = make(map[string]apidef.AuthConfig)

	a := apidef.AuthConfig{}
	Fill(t, &a, 0)
	api.AuthConfigs[apidef.AuthTokenType] = a

	sw := &OAS{}
	sw.Fill(api)

	var converted apidef.APIDefinition
	sw.ExtractTo(&converted)

	assert.Equal(t, api.AuthConfigs, converted.AuthConfigs)
}

func TestValidateOASObject(t *testing.T) {
	var validOAS3Definition = []byte(`{
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
			"tags": [
			  "pets"
			],
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
			],
			"responses": {
			  "200": {
				"description": "A paged array of pets",
				"headers": {
				  "x-next": {
					"description": "A link to the next page of responses",
					"schema": {
					  "type": "string"
					}
				  }
				},
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Pets"
					}
				  }
				}
			  },
			  "default": {
				"description": "unexpected error",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Error"
					}
				  }
				}
			  }
			}
		  },
		  "post": {
			"summary": "Create a pet",
			"operationId": "createPets",
			"tags": [
			  "pets"
			],
			"responses": {
			  "201": {
				"description": "Null response"
			  },
			  "default": {
				"description": "unexpected error",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Error"
					}
				  }
				}
			  }
			}
		  }
		},
		"/pets/{petId}": {
		  "get": {
			"summary": "Info for a specific pet",
			"operationId": "showPetById",
			"tags": [
			  "pets"
			],
			"parameters": [
			  {
				"name": "petId",
				"in": "path",
				"required": true,
				"description": "The id of the pet to retrieve",
				"schema": {
				  "type": "string"
				}
			  }
			],
			"responses": {
			  "200": {
				"description": "Expected response to a valid request",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Pet"
					}
				  }
				}
			  },
			  "default": {
				"description": "unexpected error",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Error"
					}
				  }
				}
			  }
			}
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

	var invalidOAS3Definition = []byte(`{
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
		  },
		  "post": {
			"summary": "Create a pet",
			"operationId": "createPets",
			"tags": [
			  "pets"
			],
			"responses": {
			  "201": {
				"description": "Null response"
			  },
			  "default": {
				"description": "unexpected error",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Error"
					}
				  }
				}
			  }
			}
		  }
		},
		"/pets/{petId}": {
		  "get": {
			"summary": "Info for a specific pet",
			"operationId": "showPetById",
			"tags": [
			  "pets"
			],
			"parameters": [
			  {
				"name": "petId",
				"in": "path",
				"required": true,
				"description": "The id of the pet to retrieve",
				"schema": {
				  "type": "string"
				}
			  }
			],
			"responses": {
			  "200": {
				"description": "Expected response to a valid request",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Pet"
					}
				  }
				}
			  },
			  "default": {
				"description": "unexpected error",
				"content": {
				  "application/json": {
					"schema": {
					  "$ref": "#/components/schemas/Error"
					}
				  }
				}
			  }
			}
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

	t.Run("valid OAS object", func(t *testing.T) {
		isValid, errs := ValidateOASObject(validOAS3Definition, "3.0")
		assert.True(t, isValid)
		assert.Nil(t, errs)
	})

	t.Run("invalid OAS object", func(t *testing.T) {
		isValid, errs := ValidateOASObject(invalidOAS3Definition, "3.0")
		expectedErrs := []string{
			"paths./pets.get: responses is required",
			"paths./pets.get.tags: Invalid type. Expected: array, given: string",
		}
		assert.False(t, isValid)
		assert.Equal(t, expectedErrs, errs)
	})
}
