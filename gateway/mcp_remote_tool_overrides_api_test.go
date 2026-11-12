package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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

	_, err = ts.Run(t, []test.TestCase{
		{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/mcps", Data: body(`true`), Code: http.StatusOK},
		{AdminAuth: true, Method: http.MethodPut, Path: "/tyk/mcps/remote-mcp-hint-api", Data: body(`"yes"`),
			Code: http.StatusBadRequest, BodyMatch: `destructiveHint`},
	}...)
	require.NoError(t, err)
}

func TestMCPAPI_RemoteToolNameAndDescriptionOverrideRoundTrip(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	const description = "Open a new issue in a repository. Requires the repository name and a title."
	body := `{
		"openapi": "3.0.3",
		"info": {"title": "GitHub MCP", "version": "1.0.0"},
		"paths": {},
		"x-tyk-api-gateway": {
			"info": {"id": "github-mcp", "name": "github-mcp", "state": {"active": true}},
			"upstream": {"url": "https://mcp.example.com/mcp"},
			"server": {"listenPath": {"value": "/github-mcp/", "strip": true}}
		},
		"x-tyk-mcp-server": {"primitives": [
			{"source": {"toolName": "create_issue"}, "name": "open_issue", "description": "` + description + `"}
		]}
	}`

	_, err := ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: "/tyk/mcps", Data: body, Code: http.StatusOK})
	require.NoError(t, err)
	ts.Gw.DoReload()

	res, err := ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/mcps/github-mcp", Code: http.StatusOK})
	require.NoError(t, err)
	stored, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var doc struct {
		Server struct {
			Primitives []json.RawMessage `json:"primitives"`
		} `json:"x-tyk-mcp-server"`
	}
	require.NoError(t, json.Unmarshal(stored, &doc), string(stored))
	require.Len(t, doc.Server.Primitives, 1, string(stored))
	assert.JSONEq(t, `{"source":{"toolName":"create_issue"},"name":"open_issue","description":"`+description+`"}`, string(doc.Server.Primitives[0]))
}
