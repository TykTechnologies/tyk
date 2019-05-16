package importer

import (
	"bytes"
	"testing"
)

func TestToAPIDefinition_Swagger(t *testing.T) {
	imp, err := GetImporterForSource(SwaggerSource)
	if err != nil {
		t.Fatal(err)
	}

	buff := bytes.NewBufferString(petstoreJSON)

	err = imp.LoadFrom(buff)
	if err != nil {
		t.Fatal(err)
	}

	def, err := imp.ToAPIDefinition("testOrg", "http://test.com", false)

	if err != nil {
		t.Fatal(err)
	}

	if def.VersionData.NotVersioned {
		t.Fatal("Swagger import must always be versioned")
	}

	if len(def.VersionData.Versions) > 1 {
		t.Fatal("THere should only be one version")
	}

	v, ok := def.VersionData.Versions["1.0.0"]
	if !ok {
		t.Fatal("Version could not be found")
	}

	if len(v.ExtendedPaths.TrackEndpoints) != 3 {
		t.Fatalf("Expected 3 endpoints, found %v\n", len(v.ExtendedPaths.TrackEndpoints))
	}

}

var petstoreJSON string = `{
  "swagger": "2.0",
  "info": {
    "version": "1.0.0",
    "title": "Swagger Petstore",
    "license": {
      "name": "MIT"
    }
  },
  "host": "petstore.swagger.io",
  "basePath": "/v1",
  "schemes": [
    "http"
  ],
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
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
            "type": "integer",
            "format": "int32"
          }
        ],
        "responses": {
          "200": {
            "description": "An paged array of pets",
            "headers": {
              "x-next": {
                "type": "string",
                "description": "A link to the next page of responses"
              }
            },
            "schema": {
              "$ref": "#/definitions/Pets"
            }
          },
          "default": {
            "description": "unexpected error",
            "schema": {
              "$ref": "#/definitions/Error"
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
            "schema": {
              "$ref": "#/definitions/Error"
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
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "Expected response to a valid request",
            "schema": {
              "$ref": "#/definitions/Pets"
            }
          },
          "default": {
            "description": "unexpected error",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "Pet": {
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
        "$ref": "#/definitions/Pet"
      }
    },
    "Error": {
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
}`
