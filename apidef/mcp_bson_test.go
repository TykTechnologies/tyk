package apidef

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	mongobson "go.mongodb.org/mongo-driver/bson"
	mgobson "gopkg.in/mgo.v2/bson"
)

func TestMCPBSONStorageSemantics(t *testing.T) {
	for _, codec := range []struct {
		name      string
		marshal   func(interface{}) ([]byte, error)
		unmarshal func([]byte, interface{}) error
	}{{"mongo-go", mongobson.Marshal, mongobson.Unmarshal}, {"mgo", mgobson.Marshal, mgobson.Unmarshal}} {
		t.Run(codec.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				raw  map[string]interface{}
				want *MCPConfig
			}{
				{"old absent field", map[string]interface{}{}, nil},
				{"null field", map[string]interface{}{"mcp": nil}, nil},
				{"explicit empty object", map[string]interface{}{"mcp": map[string]interface{}{}}, &MCPConfig{}},
				{"explicit empty list", map[string]interface{}{"mcp": map[string]interface{}{"trusted_origins": []string{}}}, &MCPConfig{TrustedOrigins: []string{}}},
				{"explicit trust", map[string]interface{}{"mcp": map[string]interface{}{"trusted_origins": []string{"https://client.example"}}}, &MCPConfig{TrustedOrigins: []string{"https://client.example"}}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					data, err := codec.marshal(tc.raw)
					require.NoError(t, err)
					var api APIDefinition
					require.NoError(t, codec.unmarshal(data, &api))
					require.Equal(t, tc.want, api.MCP)
					data, err = codec.marshal(api)
					require.NoError(t, err)
					var stored map[string]interface{}
					require.NoError(t, codec.unmarshal(data, &stored))
					require.Contains(t, stored, "mcp", "nil must overwrite old values in a $set update")
					public, err := json.Marshal(api)
					require.NoError(t, err)
					var publicFields map[string]interface{}
					require.NoError(t, json.Unmarshal(public, &publicFields))
					if tc.want == nil {
						require.Nil(t, stored["mcp"])
						require.NotContains(t, publicFields, "mcp", "non-MCP public JSON stays unchanged")
					} else {
						require.NotNil(t, stored["mcp"])
						var roundTrip APIDefinition
						require.NoError(t, codec.unmarshal(data, &roundTrip))
						require.NotNil(t, roundTrip.MCP, "explicit empty must not become absence")
						require.Equal(t, tc.want.TrustedOrigins, api.MCP.TrustedOrigins)
					}
				})
			}
		})
	}
}
