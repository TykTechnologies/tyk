package streams

import (
	"fmt"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/apidef/streams/bento"
)

// Verifies: SYS-REQ-104, SW-REQ-096
// SW-REQ-096:nominal:nominal
// SW-REQ-096:boundary:nominal
// SW-REQ-096:error_handling:nominal
// SW-REQ-096:error_handling:negative
// SW-REQ-096:determinism:nominal
func TestStreamsValidatorPreservesSupportBehavior(t *testing.T) {
	t.Run("schema loading merges stream extensions and selects versions deterministically", func(t *testing.T) {
		require.NoError(t, loadSchemas())
		require.NotEmpty(t, oasJSONSchemas["3.0"])
		require.NotEmpty(t, oasJSONSchemas["3.1"])
		require.NotNil(t, bentoValidators[bento.DefaultValidator])
		require.NotNil(t, bentoValidators[bento.EnableAllExperimental])

		for _, version := range []string{"3.0", "3.1"} {
			schema := oasJSONSchemas[version]
			_, _, _, err := jsonparser.Get(schema, keyProperties, oas.ExtensionTykStreaming)
			assert.NoError(t, err)
			_, _, _, err = jsonparser.Get(schema, keyProperties, oas.ExtensionTykAPIGateway)
			assert.NoError(t, err)

			defsKey := oas.GetDefinitionsKey(schema)
			_, _, _, err = jsonparser.Get(schema, defsKey, "X-Tyk-Streams")
			assert.NoError(t, err)
			_, _, _, err = jsonparser.Get(schema, defsKey, "X-Tyk-Info")
			assert.NoError(t, err)
		}

		assert.Equal(t, "3.1", findDefaultVersion([]string{"3.0", "2.0", "3.1.0"}))
		setDefaultVersion()
		assert.Equal(t, "3.0", defaultVersion)

		versionTests := []struct {
			name        string
			requested   string
			wantMinor   string
			wantDefsKey string
		}{
			{
				name:        "default version uses overridden 3.0 schema",
				requested:   "",
				wantMinor:   defaultVersion,
				wantDefsKey: keyDefinitions,
			},
			{
				name:        "patch version resolves to 3.0 schema",
				requested:   "3.0.8",
				wantMinor:   "3.0",
				wantDefsKey: keyDefinitions,
			},
			{
				name:        "major-only version resolves to 3.0 schema",
				requested:   "3",
				wantMinor:   "3.0",
				wantDefsKey: keyDefinitions,
			},
			{
				name:        "3.1 patch version resolves to defs schema",
				requested:   "3.1.0",
				wantMinor:   "3.1",
				wantDefsKey: keyDefs,
			},
		}

		for _, tt := range versionTests {
			t.Run(tt.name, func(t *testing.T) {
				schema, err := GetOASSchema(tt.requested)
				require.NoError(t, err)
				assert.Equal(t, oasJSONSchemas[tt.wantMinor], schema)
				assert.Equal(t, tt.wantDefsKey, oas.GetDefinitionsKey(schema))
			})
		}
	})

	t.Run("version and document validation errors remain explicit", func(t *testing.T) {
		_, err := GetOASSchema("4.0.0")
		assert.EqualError(t, err, fmt.Sprintf(oasSchemaVersionNotFoundFmt, "4.0.0"))

		_, err = GetOASSchema("not-semver")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed version")

		err = ValidateOASObject([]byte(`{"openapi":"3.0.3"`), "3.0.3")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected EOF")

		invalidDocument := []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "test streams", "version": "1.0.0"},
			"paths": {},
			"x-tyk-streaming": {},
			"x-tyk-api-gateway": {}
		}`)
		err = ValidateOASObject(invalidDocument, "3.0.3")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x-tyk-api-gateway")
		assert.Contains(t, err.Error(), "x-tyk-streaming")
	})

	t.Run("object and template validators preserve stream-specific behavior", func(t *testing.T) {
		require.NoError(t, ValidateOASObject(streamsValidatorDocument(`true`), "3.0.3"))
		require.NoError(t, ValidateOASObjectWithConfig(streamsValidatorDocument(`true`), "3.0.3", false))

		template := []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "template", "version": "1.0.0"},
			"paths": {},
			"x-tyk-streaming": {},
			"x-tyk-api-gateway": {}
		}`)
		require.NoError(t, ValidateOASTemplate(template, "3.0.3"))
		require.NoError(t, ValidateOASTemplateWithBentoValidator(template, "3.0.3", bento.EnableAllExperimental))

		assert.NoError(t, validateBentoConfiguration([]byte(`{"x-tyk-streaming":{}}`), bento.DefaultValidator))
	})

	t.Run("bento validator selection reports or bypasses per-stream errors", func(t *testing.T) {
		invalidBentoDocument := streamsValidatorDocument(`"true"`)
		modeTests := []struct {
			name          string
			validatorKind bento.ValidatorKind
			wantErr       bool
		}{
			{
				name:          "default validator reports stream-scoped bento errors",
				validatorKind: bento.DefaultValidator,
				wantErr:       true,
			},
			{
				name:          "enable-all validator bypasses bento validation",
				validatorKind: bento.EnableAllExperimental,
				wantErr:       false,
			},
		}

		for _, tt := range modeTests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateOASObjectWithBentoConfigValidator(invalidBentoDocument, "3.0.3", tt.validatorKind)
				if tt.wantErr {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "test-kafka-stream")
					assert.Contains(t, err.Error(), "input.kafka.auto_replay_nacks")
					return
				}
				require.NoError(t, err)
			})
		}

		require.NoError(t, ValidateOASObjectWithConfig(invalidBentoDocument, "3.0.3", true))
	})
}

func streamsValidatorDocument(autoReplayNacks string) []byte {
	return []byte(`{
		"openapi": "3.0.3",
		"info": {"title": "test streams", "version": "1.0.0"},
		"paths": {},
		"x-tyk-streaming": {
			"streams": {
				"test-kafka-stream": {
					"input": {
						"kafka": {
							"addresses": [],
							"topics": [],
							"target_version": "2.1.0",
							"consumer_group": "",
							"checkpoint_limit": 1024,
							"auto_replay_nacks": ` + autoReplayNacks + `
						}
					}
				}
			}
		},
		"x-tyk-api-gateway": {
			"info": {
				"name": "test-streams",
				"state": {"active": true}
			},
			"server": {
				"listenPath": {"value": "/test-streams"}
			}
		}
	}`)
}
