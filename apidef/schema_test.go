package apidef

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Verifies: SW-REQ-033
// SW-REQ-033:nominal:nominal
// SW-REQ-033:boundary:nominal
// SW-REQ-033:boundary:boundary
func TestSchemaEmbeddedDocument(t *testing.T) {
	require.NotEmpty(t, Schema)

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(Schema), &doc))

	require.Equal(t, "http://json-schema.org/draft-04/schema", doc["$schema"])
	require.Equal(t, "http://jsonschema.net", doc["id"])
	require.Contains(t, doc, "properties")
}
