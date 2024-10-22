package streams

import (
	"embed"
	"fmt"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/buger/jsonparser"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/warpstreamlabs/bento/public/components/io"
	_ "github.com/warpstreamlabs/bento/public/components/kafka"
)

//go:embed testdata/*-oas-template.json
var oasTemplateFS embed.FS

func TestValidateTykStreamsOASObject(t *testing.T) {
	t.Parallel()
	validOASObject := oas.OAS{
		T: openapi3.T{
			OpenAPI:    "3.0.3",
			Info:       &openapi3.Info{},
			Paths:      map[string]*openapi3.PathItem{},
			Extensions: map[string]interface{}{},
		},
	}

	validXTykAPIStreaming := XTykStreaming{
		Info: oas.Info{
			Name: "test-streams",
			State: oas.State{
				Active: true,
			},
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/test-streams",
			},
		},
		Streams: map[string]interface{}{},
	}

	validOASObject.Extensions[ExtensionTykStreaming] = &validXTykAPIStreaming

	validOAS3Definition, _ := validOASObject.MarshalJSON()

	t.Run("valid Tyk Streaming Extension", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS3Definition, "3.0.3")
		assert.Nil(t, err)
	})

	invalidOASObject := validOASObject
	invalidXTykAPIGateway := validXTykAPIStreaming
	invalidXTykAPIGateway.Info = oas.Info{}
	invalidXTykAPIGateway.Server.GatewayTags = &oas.GatewayTags{Enabled: true, Tags: []string{}}
	invalidOASObject.Extensions[ExtensionTykStreaming] = &invalidXTykAPIGateway
	invalidOAS3Definition, _ := invalidOASObject.MarshalJSON()

	t.Run("invalid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(invalidOAS3Definition, "3.0.3")
		expectedErrs := []string{
			`x-tyk-streaming.info.name: Does not match pattern '\S+'`,
		}
		actualErrs := strings.Split(err.Error(), "\n")
		assert.ElementsMatch(t, expectedErrs, actualErrs)
	})

	var wrongTypedOASDefinition = []byte(`{
    "openapi": "3.0.0",
    "info": {
        "version": "1.0.0",
        "title": "Tyk Streams Example",
        "license": {
            "name": "MIT"
        }
    },
    "servers": [
        {
            "url": "http://tyk-gateway:8081/test-streams"
        }
    ],
    "paths": {},
    "x-tyk-streaming": {
        
    }
}`)

	t.Run("wrong typed OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(wrongTypedOASDefinition, "3.0.3")
		expectedErr := fmt.Sprintf("%s\n%s\n%s",
			"x-tyk-streaming: info is required",
			"x-tyk-streaming: streams is required",
			"x-tyk-streaming: server is required")
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

func TestValidateOASTemplate(t *testing.T) {
	t.Run("empty x-tyk ext", func(t *testing.T) {
		body, err := oasTemplateFS.ReadFile("testdata/empty-x-tyk-ext-oas-template.json")
		require.NoError(t, err)
		err = ValidateOASTemplate(body, "")
		assert.NoError(t, err)
	})

	t.Run("non-empty x-tyk-ext", func(t *testing.T) {
		body, err := oasTemplateFS.ReadFile("testdata/non-empty-x-tyk-ext-oas-template.json")
		require.NoError(t, err)
		err = ValidateOASTemplate(body, "")
		assert.NoError(t, err)
	})
}

func Test_loadOASSchema(t *testing.T) {
	t.Parallel()
	t.Run("load Tyk Streams OAS", func(t *testing.T) {
		t.Parallel()
		err := loadSchemas()
		assert.Nil(t, err)
		assert.NotNil(t, oasJSONSchemas)
		for oasVersion := range oasJSONSchemas {
			var xTykStreaming, xTykStreams []byte
			xTykStreaming, _, _, err = jsonparser.Get(oasJSONSchemas[oasVersion], keyProperties, ExtensionTykStreaming)
			assert.NoError(t, err)
			assert.NotNil(t, xTykStreaming)

			xTykStreams, _, _, err = jsonparser.Get(oasJSONSchemas[oasVersion], keyDefinitions, "X-Tyk-Streams")
			assert.NoError(t, err)
			assert.NotNil(t, xTykStreams)
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
	err := loadSchemas()
	assert.NoError(t, err)

	setDefaultVersion()
	assert.Equal(t, "3.0", defaultVersion)
}

func TestGetOASSchema(t *testing.T) {
	err := loadSchemas()
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

func TestValidateTykStreamsOASObject_Validate_Bento_Configuration(t *testing.T) {
	var document = []byte(`{
    "info": {
        "title": "",
        "version": ""
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
        "info": {
            "name": "test-streams",
            "state": {
                "active": true
            }
        },
        "server": {
            "listenPath": {
                "value": "/test-streams"
            }
        },
        "streams": {
            "test-kafka-stream": {
                "input": {
                    "label": "",
                    "kafka": {
                        "addresses": [],
                        "topics": [],
                        "target_version": "2.1.0",
                        "consumer_group": "",
                        "checkpoint_limit": 1024,
                        "auto_replay_nacks": true
                    }
                }
            }
        }
    }
}`)
	err := ValidateOASObject(document, "3.0.3")
	require.NoError(t, err)
}

func TestValidateTykStreamsOASObject_Validate_Bento_Configurations(t *testing.T) {
	var document = []byte(`{
    "info": {
        "title": "",
        "version": ""
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
        "info": {
            "name": "test-streams",
            "state": {
                "active": true
            }
        },
        "server": {
            "listenPath": {
                "value": "/test-streams"
            }
        },
        "streams": {
            "test-kafka-stream": {
                "input": {
                    "label": "",
                    "kafka": {
                        "addresses": [],
                        "topics": [],
                        "target_version": "2.1.0",
                        "consumer_group": "",
                        "checkpoint_limit": 1024,
                        "auto_replay_nacks": "true"
                    }
                }
            }
        }
    }
}`)
	err := ValidateOASObject(document, "3.0.3")
	require.ErrorContains(t, err, "test-kafka-stream: input.kafka.auto_replay_nacks: Invalid type. Expected: boolean, given: string")
}
