package gateway

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/test"
)

func TestMCPAPI_RejectsNonBooleanToolAnnotationHint(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	body := func(hint string) string {
		return `{
			"openapi": "3.0.3",
			"info": {"title": "GitHub MCP", "version": "1.0.0"},
			"paths": {},
			"x-tyk-api-gateway": {
				"info": {"id": "remote-mcp-hint-api", "name": "github", "state": {"active": true}},
				"upstream": {"url": "https://mcp.example.com/mcp"},
				"server": {"listenPath": {"value": "/github-hint/", "strip": true}}
			},
			"x-tyk-mcp-server": {"primitives": [
				{"source": {"toolName": "delete_repo"}, "annotations": {"destructiveHint": ` + hint + `}}
			]}
		}`
	}

	res, err := ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/mcps", Data: body(`"yes"`),
		Code: http.StatusBadRequest, BodyMatch: `destructiveHint`})
	require.NoError(t, err)
	rejection, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	t.Logf("rejection: %s", rejection)

	_, _ = ts.Run(t, []test.TestCase{
		{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/mcps", Data: body(`true`), Code: http.StatusOK},
		{AdminAuth: true, Method: http.MethodPut, Path: "/tyk/mcps/remote-mcp-hint-api", Data: body(`"yes"`),
			Code: http.StatusBadRequest, BodyMatch: `destructiveHint`},
	}...)
}
