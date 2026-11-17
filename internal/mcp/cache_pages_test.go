package mcp

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

func TestCredentialDependentPages(t *testing.T) {
	for key, cfg := range ListFilterConfigs {
		for _, items := range []string{`[]`, fmt.Sprintf(`[{%q:"visible"}]`, cfg.NameField), fmt.Sprintf(`[{%q:"visible"},{%q:"hidden"},{%q:"visible2"}]`, cfg.NameField, cfg.NameField, cfg.NameField)} {
			t.Run(key+items, func(t *testing.T) {
				body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":9007199254740993,"extension":{"n":9007199254740995},"result":{%q:%s,"nextCursor":"cursor-2","extra":{"kept":true}}}`, key, items))
				filtered, changed := FilterJSONRPCBody(body, cfg, user.AccessControlRules{Blocked: []string{"hidden"}})
				require.True(t, changed, "applicable credential rules make every page private")
				var envelope map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(filtered, &envelope))
				require.Equal(t, "9007199254740993", string(envelope["id"]))
				require.JSONEq(t, `{"n":9007199254740995}`, string(envelope["extension"]))
				var result map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(envelope["result"], &result))
				require.Equal(t, `"private"`, string(result["cacheScope"]))
				require.Equal(t, `0`, string(result["ttlMs"]))
				require.Equal(t, `"cursor-2"`, string(result["nextCursor"]))
				require.NotContains(t, string(result[key]), "hidden")
				if items != "[]" {
					require.Contains(t, string(result[key]), "visible")
				}
			})
		}
	}
}
