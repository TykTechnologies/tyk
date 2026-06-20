package oas

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-104, SW-REQ-060
// SW-REQ-060:nominal:nominal
// SW-REQ-060:boundary:nominal
// SW-REQ-060:error_handling:negative
// SW-REQ-060:determinism:nominal
func TestOASValidatorPreservesSchemaValidationBehavior(t *testing.T) {
	t.Run("definition keys schema loading and version selection are deterministic", func(t *testing.T) {
		assert.Equal(t, keyDefs, GetDefinitionsKey([]byte(`{"$defs":{},"definitions":{}}`)))
		assert.Equal(t, keyDefinitions, GetDefinitionsKey([]byte(`{"definitions":{}}`)))
		assert.Equal(t, keyDefinitions, GetDefinitionsKey([]byte(`{"properties":{}}`)))

		require.NoError(t, loadOASSchema())
		require.NotEmpty(t, oasJSONSchemas["3.0"])
		require.NotEmpty(t, oasJSONSchemas["3.1"])

		assert.Equal(t, "3.1", findDefaultVersion([]string{"3.0", "3.1.0", "2.0"}))
		setDefaultVersion()
		assert.Equal(t, "3.0", defaultVersion)

		minor, err := getMinorVersion("3.0.8")
		require.NoError(t, err)
		assert.Equal(t, "3.0", minor)
		minor, err = getMinorVersion("3")
		require.NoError(t, err)
		assert.Equal(t, "3.0", minor)

		defaultSchema, err := GetOASSchema("")
		require.NoError(t, err)
		assert.Equal(t, oasJSONSchemas[defaultVersion], defaultSchema)
		schema31, err := GetOASSchema("3.1.0")
		require.NoError(t, err)
		assert.Equal(t, keyDefs, GetDefinitionsKey(schema31))

		_, err = GetOASSchema("4.0.0")
		assert.EqualError(t, err, fmt.Sprintf(oasSchemaVersionNotFoundFmt, "4.0.0"))
		_, err = GetOASSchema("not-semver")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed version")
	})

	t.Run("json and oas validation accept valid documents and report aggregated errors", func(t *testing.T) {
		schema := []byte(`{
			"type": "object",
			"required": ["name", "count"],
			"properties": {
				"name": {"type": "string"},
				"count": {"type": "integer"}
			}
		}`)
		require.NoError(t, validateJSON(schema, []byte(`{"name":"pets","count":2}`)))
		err := validateJSON(schema, []byte(`{"name":7}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
		assert.Contains(t, err.Error(), "count")

		validOAS := []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "Pets", "version": "1.0.0"},
			"paths": {
				"/pets": {
					"get": {
						"responses": {
							"200": {"description": "ok"}
						}
					}
				}
			},
			"x-tyk-api-gateway": {
				"info": {"name": "pets", "state": {"active": true}},
				"server": {"listenPath": {"value": "/pets"}},
				"upstream": {"url": "https://upstream.example.com"}
			}
		}`)
		require.NoError(t, ValidateOASObject(validOAS, "3.0.3"))

		invalidOAS := []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "Pets", "version": "1.0.0"},
			"paths": {"/pets": {"get": {}}},
			"x-tyk-api-gateway": {
				"info": {"name": "", "state": {"active": true}},
				"server": {"listenPath": {"value": "/pets"}},
				"upstream": {"url": "https://upstream.example.com"}
			}
		}`)
		err = ValidateOASObject(invalidOAS, "3.0.3")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "responses is required")
		assert.Contains(t, err.Error(), "x-tyk-api-gateway.info.name")

		template := []byte(`{
			"openapi": "3.0.3",
			"info": {"title": "Template", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {}
		}`)
		require.NoError(t, ValidateOASTemplate(template, "3.0.3"))

		err = ValidateOASTemplate([]byte(`{"openapi":"3.0.3"`), "3.0.3")
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "invalid character") || strings.Contains(err.Error(), "unexpected EOF"))
	})
}
