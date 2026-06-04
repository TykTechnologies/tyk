package gateway

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
)

func TestHandleDeleteAPI_RefusesRESTSourceWithPairedMCPProxy(t *testing.T) {
	gw := &Gateway{
		apisByID: map[string]*APISpec{},
	}
	gw.SetConfig(config.Config{AppPath: t.TempDir()})

	rest := restSourceSpec("rest-delete", "org-1", true)
	proxy1 := pairedMCPProxySpec("proxy-delete-1", "org-1", "rest-delete", nil)
	proxy2 := pairedMCPProxySpec("proxy-delete-2", "org-1", "rest-delete", nil)

	gw.apisByID[rest.APIID] = rest
	gw.apisByID[proxy1.APIID] = proxy1
	gw.apisByID[proxy2.APIID] = proxy2

	obj, code := gw.handleDeleteAPI("rest-delete")
	require.Equal(t, http.StatusConflict, code)

	msg, ok := obj.(apiStatusMessage)
	require.True(t, ok)
	assert.Equal(t, "error", msg.Status)
	assert.Contains(t, msg.Message, "paired MCP proxies")
	assert.Contains(t, msg.Message, "proxy-delete-1")
	assert.Contains(t, msg.Message, "proxy-delete-2")
}

func TestHandleDeleteMCP_DeletesPairedProxyPersistedWithOASSuffix(t *testing.T) {
	fs := afero.NewMemMapFs()
	appPath := "/app"
	require.NoError(t, fs.MkdirAll(appPath, 0755))

	gw := &Gateway{
		apisByID: map[string]*APISpec{},
	}
	gw.SetConfig(config.Config{AppPath: appPath})

	proxy := pairedMCPProxySpec("proxy-delete", "org-1", "rest-1", nil)
	gw.apisByID[proxy.APIID] = proxy

	mainFile := filepath.Join(appPath, "proxy-delete.json")
	mcpFile := filepath.Join(appPath, "proxy-delete-mcp.json")
	require.NoError(t, afero.WriteFile(fs, mainFile, []byte("{}"), 0644))
	require.NoError(t, afero.WriteFile(fs, mcpFile, []byte("{}"), 0644))

	obj, code := gw.handleDeleteMCP("proxy-delete", fs)
	require.Equal(t, http.StatusOK, code)

	success, ok := obj.(apiModifyKeySuccess)
	require.True(t, ok)
	assert.Equal(t, "proxy-delete", success.Key)
	assert.Equal(t, "deleted", success.Action)

	exists, err := afero.Exists(fs, mainFile)
	require.NoError(t, err)
	assert.False(t, exists)

	exists, err = afero.Exists(fs, mcpFile)
	require.NoError(t, err)
	assert.False(t, exists)
}
