package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestMCPAggregatorServesVersionedAggregatedProxyThroughItsDefaultChildVersion(t *testing.T) {
	ts, github, _ := startMCPAggregatorRuntimeTest(t)
	githubV2 := newMockRemoteMCPServer(t, "search_code")

	base := githubMCPProxyRuntimeSpec(github.URL)
	base.VersionDefinition = apidef.VersionDefinition{
		Enabled:  true,
		Name:     "v1",
		Default:  "v2",
		Location: apidef.HeaderLocation,
		Key:      "x-api-version",
		Versions: map[string]string{"v2": "github-mcp-v2"},
	}
	child := requireToken(mcpRuntimeOASSpec(mcpRuntimeDoc("github-mcp-v2", githubV2.URL), true))
	child.VersionDefinition.BaseID = "github-mcp"

	ts.Gw.LoadAPI(base, child, companyToolsRuntimeSpec(aggregated("github-mcp", "github")))

	res := postModernToolsList(t, ts, "/company-tools/", companyToolsKey(t, ts))

	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, []string{"github__search_code"}, res.tools, "the default child version serves the aggregated call")
}

func TestMCPAggregatorLoopTrustHandOverOnlyAppliesToTheBaseItWasIssuedFor(t *testing.T) {
	base := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "github-mcp"}}
	child := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "github-mcp-v2"}}
	other := &APISpec{APIDefinition: &apidef.APIDefinition{APIID: "payments-mcp"}}

	req, err := http.NewRequest(http.MethodPost, "/", nil)
	require.NoError(t, err)
	trust := &mcpAggregatorLoopTrust{UpstreamAPIID: "github-mcp"}
	ctxSetMCPAggregatorLoopTrust(req, trust)

	handOverMCPAggregatorLoopTrust(req, other, child)
	assert.Empty(t, trust.VersionAPIID, "a versioned API other than the trusted upstream does not take the trust")

	handOverMCPAggregatorLoopTrust(req, base, child)
	assert.Equal(t, "github-mcp-v2", trust.VersionAPIID)
}
