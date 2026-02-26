package streams

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/warpstreamlabs/bento/public/components/io"
	_ "github.com/warpstreamlabs/bento/public/components/kafka"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/apidef/streams/bento"
)

//go:embed testdata/*-oas-template.json
var oasTemplateFS embed.FS

func TestValidateTykStreamsOASObject(t *testing.T) {
	t.Parallel()
	validOASObject := oas.OAS{
		T: openapi3.T{
			OpenAPI:    "3.0.3",
			Info:       &openapi3.Info{},
			Paths:      openapi3.NewPaths(),
			Extensions: map[string]interface{}{},
		},
	}

	validXTykApiGateway := oas.XTykAPIGateway{
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
	}

	validXTykAPIStreaming := oas.XTykStreaming{
		Streams: map[string]interface{}{},
	}

	validOASObject.SetTykExtension(&validXTykApiGateway)
	validOASObject.SetTykStreamingExtension(&validXTykAPIStreaming)

	validOAS3Definition, _ := validOASObject.MarshalJSON()

	t.Run("Valid Tyk Streams Definition", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS3Definition, "3.0.3")
		assert.Nil(t, err)
	})

	invalidOASObject := validOASObject
	invalidXTykAPIGateway := validXTykApiGateway
	invalidXTykAPIGateway.Info = oas.Info{}
	invalidXTykAPIGateway.Server.GatewayTags = &oas.GatewayTags{Enabled: true, Tags: []string{}}
	invalidOASObject.Extensions[oas.ExtensionTykAPIGateway] = &invalidXTykAPIGateway
	invalidOAS3Definition, _ := invalidOASObject.MarshalJSON()

	t.Run("invalid OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(invalidOAS3Definition, "3.0.3")
		expectedErrs := []string{
			`x-tyk-api-gateway.info.name: Does not match pattern '\S+'`,
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
        
    },
    "x-tyk-api-gateway": {
        
    }
}`)

	t.Run("wrong typed OAS object", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(wrongTypedOASDefinition, "3.0.3")
		expectedErr := []string{
			"x-tyk-api-gateway: info is required",
			"x-tyk-api-gateway: server is required",
			"x-tyk-streaming: streams is required",
		}
		// errors are returned in a random order. Sort the array and check the equality.
		listOfErrors := strings.Split(err.Error(), "\n")
		sort.Strings(expectedErr)
		sort.Strings(listOfErrors)
		assert.Equal(t, expectedErr, listOfErrors)
	})

	t.Run("should error when requested oas schema not found", func(t *testing.T) {
		t.Parallel()
		reqOASVersion := "4.0.3"
		err := ValidateOASObject(validOAS3Definition, reqOASVersion)
		expectedErr := fmt.Errorf(oasSchemaVersionNotFoundFmt, reqOASVersion)
		assert.Equal(t, expectedErr, err)
	})
}

func TestValidateTykStreamsOASObject_3_1(t *testing.T) {
	t.Parallel()

	// Create minimal valid OAS 3.1 Tyk Streams document
	validOAS31Doc := []byte(`{
		"openapi": "3.1.0",
		"info": {
			"title": "Test Streams API 3.1",
			"version": "1.0.0"
		},
		"paths": {},
		"x-tyk-streaming": {
			"streams": {}
		},
		"x-tyk-api-gateway": {
			"info": {
				"name": "test-streams-3.1",
				"state": {
					"active": true
				}
			},
			"server": {
				"listenPath": {
					"value": "/test-streams-3.1/"
				}
			}
		}
	}`)

	t.Run("valid OAS 3.1 Tyk Streams document with version 3.1.0", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS31Doc, "3.1.0")
		assert.NoError(t, err)
	})

	t.Run("valid OAS 3.1 Tyk Streams document with version 3.1", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASObject(validOAS31Doc, "3.1")
		assert.NoError(t, err)
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

func TestValidateOASTemplate_3_1(t *testing.T) {
	t.Parallel()

	// Minimal OAS 3.1 template (missing required x-tyk fields)
	template31 := []byte(`{
		"openapi": "3.1.0",
		"info": {
			"title": "Template Streams API 3.1",
			"version": "1.0.0"
		},
		"paths": {},
		"x-tyk-streaming": {},
		"x-tyk-api-gateway": {}
	}`)

	t.Run("valid OAS 3.1 Tyk Streams template", func(t *testing.T) {
		t.Parallel()
		err := ValidateOASTemplate(template31, "3.1")
		assert.NoError(t, err)
	})
}

func Test_loadOASSchema(t *testing.T) {
	t.Parallel()
	t.Run("load Tyk Streams OAS schemas", func(t *testing.T) {
		t.Parallel()
		err := loadSchemas()
		assert.Nil(t, err)
		assert.NotNil(t, oasJSONSchemas)

		// Verify we have at least 3.0 and 3.1 schemas
		assert.Contains(t, oasJSONSchemas, "3.0", "Should load OAS 3.0 schema")
		assert.Contains(t, oasJSONSchemas, "3.1", "Should load OAS 3.1 schema")

		for oasVersion, schemaData := range oasJSONSchemas {
			// Check x-tyk-streaming extension is in properties
			var xTykStreaming []byte
			xTykStreaming, _, _, err = jsonparser.Get(schemaData, keyProperties, oas.ExtensionTykStreaming)
			assert.NoError(t, err, "x-tyk-streaming should exist in properties for version %s", oasVersion)
			assert.NotNil(t, xTykStreaming, "x-tyk-streaming should not be nil for version %s", oasVersion)

			// Detect which definitions key this version uses
			defsKey := oas.GetDefinitionsKey(schemaData)

			// Check X-Tyk-Streams is in the correct definitions location
			var xTykStreams []byte
			xTykStreams, _, _, err = jsonparser.Get(schemaData, defsKey, "X-Tyk-Streams")
			assert.NoError(t, err, "X-Tyk-Streams should exist in %s for version %s", defsKey, oasVersion)
			assert.NotNil(t, xTykStreams, "X-Tyk-Streams should not be nil for version %s", oasVersion)

			// Verify the correct key is used based on version
			if strings.HasPrefix(oasVersion, "3.0") {
				assert.Equal(t, "definitions", defsKey, "OAS 3.0 should use 'definitions'")
			} else if strings.HasPrefix(oasVersion, "3.1") {
				assert.Equal(t, "$defs", defsKey, "OAS 3.1 should use '$defs'")
			}
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

	t.Run("return 3.1 schema when version 3.1 is requested", func(t *testing.T) {
		schema, err := GetOASSchema("3.1")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)

		// Verify it's the 3.1 schema by checking it uses $defs
		defsKey := oas.GetDefinitionsKey(schema)
		assert.Equal(t, "$defs", defsKey, "OAS 3.1 schema should use $defs")
	})

	t.Run("return 3.1 schema when version 3.1.0 is requested", func(t *testing.T) {
		schema, err := GetOASSchema("3.1.0")
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)

		// Verify it's the 3.1 schema
		defsKey := oas.GetDefinitionsKey(schema)
		assert.Equal(t, "$defs", defsKey)
	})
}

func TestValidateTykStreams_BentoConfigValidation(t *testing.T) {
	var document = []byte(`{
    "info": {
        "title": "test streams",
        "version": "1.0.0"
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
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
                },
				"pipeline": {
					"processors": [
						{
							"bloblang": "root = this \n root.fans = this.fans.filter(fan -> fan.obsession > 0.5)"
						}
					]
				}
            }
        }
    },
    "x-tyk-api-gateway": {
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
        }
    }
}`)
	err := ValidateOASObject(document, "3.0.3")
	require.NoError(t, err)
}

func TestValidateTykStreams_BentoConfigValidation_Invalid_Config(t *testing.T) {
	var document = []byte(`{
    "info": {
        "title": "test-streams",
        "version": "1.0.0"
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
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
                }, 
				"pipeline": {
					"bloblang": "root = this \n root.fans = this.fans.filter(fan -> fan.obsession > 0.5)"
				}
            }
        }
    },
    "x-tyk-api-gateway": {
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
        }
    }
}`)
	err := ValidateOASObject(document, "3.0.3")
	require.ErrorContains(t, err, "input.kafka.auto_replay_nacks: Invalid type. Expected: boolean, given: string")
	require.ErrorContains(t, err, "pipeline: Additional property bloblang is not allowed")
}

func TestValidateTykStreams_BentoConfigValidation_Additional_Properties(t *testing.T) {
	// Currently, we only support Kafka as input. The following document includes unsupported input & output methods,
	// but it doesn't break the validation process.
	var document = []byte(`{
    "info": {
        "title": "test-streams",
        "version": "1.0.0"
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
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
            },
            "test-mongodb-stream": {
                "input": {
                    "label": "",
                    "mongodb": {
                        "url": "mongodb://localhost:27017",
                        "database": "",
                        "username": "",
                        "password": "",
                        "collection": "",
                        "query": "  root.from = {\"$lte\": timestamp_unix()}\n  root.to = {\"$gte\": timestamp_unix()}\n",
                        "auto_replay_nacks": true,
                        "batch_size": 1000,
                        "sort": {},
                        "limit": 0
                    }
                },
                "output": {
                    "label": "",
                    "redis_streams": {
                        "url": "redis://:6397",
                        "stream": "",
                        "body_key": "body",
                        "max_length": 0,
                        "max_in_flight": 64,
                        "metadata": {
                            "exclude_prefixes": []
                        },
                        "batching": {
                            "count": 0,
                            "byte_size": 0,
                            "period": "",
                            "check": ""
                        }
                    }
                }
            },
            "some-stream": {
                "input": {
                    "some-key": "some-value"
                }
            }
        }
    },
    "x-tyk-api-gateway": {
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
        }
    }
}`)
	t.Run("with default validator", func(t *testing.T) {
		err := ValidateOASObjectWithBentoConfigValidator(document, "3.0.3", bento.DefaultValidator)
		require.NoError(t, err)
	})

	t.Run("with enable-all validator", func(t *testing.T) {
		err := ValidateOASObjectWithBentoConfigValidator(document, "3.0.3", bento.EnableAllExperimental)
		require.NoError(t, err)

		// Test with aws_sns output configuration, it's not officially supported by Tyk Streams.
		var amqpDocument = []byte(`{
    "info": {
        "title": "test-streams",
        "version": "1.0.0"
    },
    "openapi": "3.0.3",
    "paths": {},
    "x-tyk-streaming": {
        "streams": {
            "test-enable-all-stream": {
                "input": {
                    "label": "",
                    "kafka": {
                        "addresses": [],
                        "topics": [],
                        "target_version": "2.1.0",
                        "consumer_group": "",
                        "checkpoint_limit": 1024,
                        "auto_replay_nacks": true
                    },
                    "additional": {
                        "configuration": true
                    }
                },
                "output": {
                    "label": "",
                    "drop_on": {
                        "error": false,
                        "error_patterns": [],
                        "back_pressure": "30s",
                        "output": null
                    },
                    "aws_sns": {
                        "topic_arn": "",
                        "message_group_id": "",
                        "message_deduplication_id": "",
                        "max_in_flight": 64,
                        "metadata": {
                            "exclude_prefixes": []
                        }
                    }
                }
            }
        }
    },
    "x-tyk-api-gateway": {
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
        }
    }
}`)
		err = ValidateOASObjectWithBentoConfigValidator(amqpDocument, "3.0.3", bento.EnableAllExperimental)
		require.NoError(t, err)

		// This method is used by the Dashboard, so we need to test it as well.
		err = ValidateOASObjectWithConfig(amqpDocument, "3.0.3", true)
		require.NoError(t, err)
	})
}
