package keys

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/user"
)

// The JSON below is the shape the Dashboard serves from /system/policies.
const dashboardPolicyJSON = `{
  "_id": "6500000000000000000000aa",
  "id": "pol-a",
  "org_id": "default",
  "rate": 100,
  "per": 60,
  "quota_max": 10,
  "quota_renewal_rate": 3600,
  "active": true,
  "key_expires_in": 0,
  "access_rights": {
    "api-a": {
      "api_name": "api-a",
      "api_id": "api-a",
      "versions": ["Default"],
      "allowed_urls": [{"url": "/ok", "methods": ["GET"]}],
      "limit": {"rate": 5, "per": 1, "quota_max": 1, "quota_renewal_rate": 60},
      "json_rpc_methods": [{"name": "tools/call", "rate": 1, "per": 1}],
      "mcp_primitives": [{"name": "echo", "type": "tool", "rate": 2, "per": 1}]
    },
    "api-b": {
      "api_id": "api-b",
      "versions": ["Default"]
    }
  }
}`

func TestDBPolicy_ToRegularPolicy(t *testing.T) {
	var dbPol DBPolicy
	require.NoError(t, json.Unmarshal([]byte(dashboardPolicyJSON), &dbPol))

	pol := dbPol.ToRegularPolicy()

	assert.Equal(t, "pol-a", pol.ID)
	assert.Equal(t, "default", pol.OrgID)
	assert.Equal(t, float64(100), pol.Rate)
	assert.Len(t, pol.AccessRights, 2)

	a := pol.AccessRights["api-a"]
	assert.Equal(t, "api-a", a.APIName)
	assert.Equal(t, []string{"Default"}, a.Versions)
	assert.Equal(t, []user.AccessSpec{{URL: "/ok", Methods: []string{"GET"}}}, a.AllowedURLs)
	assert.Equal(t, user.APILimit{RateLimit: user.RateLimit{Rate: 5, Per: 1}, QuotaMax: 1, QuotaRenewalRate: 60}, a.Limit)
	assert.Len(t, a.JSONRPCMethods, 1)
	assert.Len(t, a.MCPPrimitives, 1)

	// A nil limit converts to the zero APILimit, which the policy service
	// treats as "no per-API limit".
	b := pol.AccessRights["api-b"]
	assert.Equal(t, user.APILimit{}, b.Limit)
	assert.Equal(t, "api-b", b.APIID)
}
