package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteMCPProxyAllowedOnceItsAggregatorIsDeletedThroughTheAPIsEndpointBeforeReload(t *testing.T) {
	gw, appPath := mcpAggregatorDeleteGuardGateway(t)
	// handleDeleteAPI removes an OAS API's definition and its -oas document.
	require.NoError(t, os.WriteFile(filepath.Join(appPath, "company-tools-oas.json"), []byte("{}"), 0o600))

	_, code := gw.handleDeleteAPI("company-tools")
	require.Equal(t, http.StatusOK, code)

	w := deleteMCPProxyThroughAPI(gw, "orders")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestMCPAggregatorWritesMadeWhileAReloadRunsOutliveIt(t *testing.T) {
	gw, _ := mcpAggregatorDeleteGuardGateway(t)

	// The reload reads its definitions, then the Gateway API creates an
	// aggregator before the reload builds the index from what it read.
	gw.mcpAggregatorWrites.definitionsRead()
	writeMCPAggregatorThroughAPI(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme", aggregated("github", "github")))
	gw.mcpAggregatorWrites.loaded()

	writeMCPAggregatorThroughAPI(t, gw, http.MethodPut, mcpAggregatorOAS("company-tools", "acme", aggregated("orders", "orders")))
	w := deleteMCPProxyThroughAPI(gw, "github")
	assert.Equal(t, http.StatusConflict, w.Code, "the write the reload did not read still guards: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), `API \"github\" is referenced by MCP aggregators: all-tools`)

	// A later reload reads it.
	gw.mcpAggregatorWrites.definitionsRead()
	gw.mcpAggregatorWrites.loaded()
	gw.mcpAggregatorWrites.mu.Lock()
	assert.Empty(t, gw.mcpAggregatorWrites.entries)
	gw.mcpAggregatorWrites.mu.Unlock()
}

func TestMCPAggregatorWritesLoadedWithoutAReadAreAllDropped(t *testing.T) {
	var writes mcpAggregatorWrites
	aggregator := mcpAggregatorSpec("all-tools", "acme", aggregated("github", "github"))
	writes.written("all-tools", aggregator.APIDefinition, &aggregator.OAS)
	assert.Equal(t, []string{"all-tools"}, writes.referencing("github", nil))

	writes.loaded()

	assert.Empty(t, writes.referencing("github", nil))
}

func TestMCPAggregatorWritesIgnoreAnAggregatorExtensionOnANonMCPDefinition(t *testing.T) {
	var writes mcpAggregatorWrites
	aggregator := mcpAggregatorSpec("all-tools", "acme", aggregated("github", "github"))
	plain := *aggregator.APIDefinition
	plain.ApplicationProtocol = ""

	writes.written("all-tools", &plain, &aggregator.OAS)

	assert.Empty(t, writes.referencing("github", []string{"all-tools"}), "a non-MCP definition is not an aggregator once loaded")
}

func TestMCPAggregatorUpdateConflictFollowsAggregatorsWrittenSinceReload(t *testing.T) {
	gw, _ := mcpAggregatorDeleteGuardGateway(t)

	writeMCPAggregatorThroughAPI(t, gw, http.MethodPut, mcpAggregatorOAS("company-tools", "acme", aggregated("github", "github")))
	api, doc := mcpProxyUpdate("globex", true)
	api.APIID = "orders"
	msg, code := gw.mcpAggregatorUpdateConflict("orders", api, doc)
	assert.Empty(t, msg, "company-tools no longer references orders")
	assert.Zero(t, code)

	writeMCPAggregatorThroughAPI(t, gw, http.MethodPost, mcpAggregatorOAS("all-tools", "acme", aggregated("orders", "orders")))
	msg, code = gw.mcpAggregatorUpdateConflict("orders", api, doc)
	assert.Equal(t, http.StatusConflict, code)
	assert.Contains(t, msg, `API "orders" is referenced by MCP aggregators: all-tools`)
}
