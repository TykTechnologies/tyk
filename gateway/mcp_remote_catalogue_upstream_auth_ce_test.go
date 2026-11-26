//go:build !ee && !dev

package gateway

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestRemoteMCPCatalogue_UpstreamAuthOnCommunityEdition(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)
	const apiID = "remote-mcp-catalogue-ce-auth"
	logs := recordRemoteMCPLogs(t, apiID)
	upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

	spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
		spec.UpstreamAuth = apidef.UpstreamAuth{
			Enabled:   true,
			BasicAuth: apidef.UpstreamBasicAuth{Enabled: true, Username: "catalogue", Password: "check"},
		}
		spec.OAS.Fill(*spec.APIDefinition)
	})
	waitForRemoteMCPToolViewCheck(t, spec)

	assertCatalogueListed(t, logs)
	assert.Empty(t, seen.get("Authorization"), "upstream basic auth is an Enterprise Edition feature, on the proxy and on the check")
	assert.LessOrEqual(t, logs.count(logrus.ErrorLevel, "supported only in Tyk Enterprise Edition"), 1,
		"the check must not repeat the proxy chain's Enterprise Edition error")
}
